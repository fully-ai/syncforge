use crate::catalog::{BackupProfile, Catalog, FileManifestEntry, SnapshotRecord};
use crate::crypto::{create_manifest, open_chunk, seal_chunk, sha256_hex, unlock_manifest, RepoManifest};
use crate::storage::{LocalBackend, S3Backend, S3Config, StorageBackend};
use chrono::Utc;
use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::UNIX_EPOCH;
use walkdir::WalkDir;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoStatsReport {
    pub snapshots_total: usize,
    pub snapshots_completed: usize,
    pub unique_chunks: usize,
    pub total_logical_bytes: i64,
    pub total_stored_bytes: i64,
    pub deduplication_savings_percent: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyReport {
    pub chunks_checked: usize,
    pub snapshots_checked: usize,
    pub healthy: bool,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreReport {
    pub snapshot_id: String,
    pub dry_run: bool,
    pub files_restored: usize,
    pub bytes_restored: u64,
    pub files: Vec<String>,
}

pub fn init_repository(
    repo_dir: &Path,
    passphrase: &str,
    chunk_size: usize,
) -> Result<RepoManifest, String> {
    if passphrase.len() < 6 {
        return Err("passphrase must be at least 6 characters".to_string());
    }
    fs::create_dir_all(repo_dir).map_err(|e| format!("create repo dir: {e}"))?;
    let manifest_path = repo_dir.join("repo.json");
    if manifest_path.exists() {
        return Err("repository already initialized".to_string());
    }
    let (manifest, _key) = create_manifest(passphrase, chunk_size.max(4096));
    let json = serde_json::to_string_pretty(&manifest).map_err(|e| format!("json: {e}"))?;
    fs::write(&manifest_path, json).map_err(|e| format!("write manifest: {e}"))?;
    let _ = Catalog::open(&repo_dir.join("catalog.db"))?;
    let _ = LocalBackend::new(repo_dir)?;
    Ok(manifest)
}

pub type OpenedRepo = (RepoManifest, [u8; 32], Catalog, Box<dyn StorageBackend>);

pub fn open_repo(
    repo_dir: &Path,
    passphrase: &str,
    s3_cfg: Option<S3Config>,
) -> Result<OpenedRepo, String> {
    let raw = fs::read_to_string(repo_dir.join("repo.json"))
        .map_err(|e| format!("read repo.json: {e}"))?;
    let manifest: RepoManifest =
        serde_json::from_str(&raw).map_err(|e| format!("parse repo.json: {e}"))?;
    let key = unlock_manifest(&manifest, passphrase)?;
    let catalog = Catalog::open(&repo_dir.join("catalog.db"))?;
    let backend: Box<dyn StorageBackend> = match s3_cfg {
        Some(cfg) => Box::new(S3Backend::new(cfg)),
        None => Box::new(LocalBackend::new(repo_dir)?),
    };
    Ok((manifest, key, catalog, backend))
}

fn build_excludes(patterns: &[String]) -> Result<GlobSet, String> {
    let mut builder = GlobSetBuilder::new();
    for pat in patterns {
        let g = Glob::new(pat).map_err(|e| format!("invalid glob {pat}: {e}"))?;
        builder.add(g);
    }
    builder.build().map_err(|e| format!("build globset: {e}"))
}

fn make_snapshot_id() -> String {
    let ts = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let rnd: u32 = rand::random();
    format!("{ts}-{rnd:08x}")
}

#[allow(clippy::too_many_arguments)]
pub fn run_backup(
    repo_dir: &Path,
    passphrase: &str,
    s3_cfg: Option<S3Config>,
    profile_name: &str,
    sources: &[PathBuf],
    excludes: &[String],
    mode: &str, // full | incremental | differential
    resume: bool,
) -> Result<SnapshotRecord, String> {
    let (manifest, key, catalog, backend) = open_repo(repo_dir, passphrase, s3_cfg)?;
    let excl = build_excludes(excludes)?;

    if !matches!(mode, "full" | "incremental" | "differential") {
        return Err(format!("invalid backup mode: {mode}"));
    }

    // Save/refresh profile definition when sources are provided
    let effective_sources: Vec<PathBuf> = if !sources.is_empty() {
        let _ = catalog.upsert_profile(&BackupProfile {
            name: profile_name.to_string(),
            sources: sources.iter().map(|p| p.to_string_lossy().to_string()).collect(),
            excludes: excludes.to_vec(),
            keep_last: 7,
        });
        sources.to_vec()
    } else if let Some(prof) = catalog.get_profile(profile_name)? {
        prof.sources.into_iter().map(PathBuf::from).collect()
    } else {
        return Err("no source paths specified and no saved profile found".to_string());
    };

    // Baseline snapshot for incremental (latest completed) or differential (latest full)
    let parent_snap = match mode {
        "incremental" => catalog.latest_completed_snapshot(profile_name, None)?,
        "differential" => catalog.latest_completed_snapshot(profile_name, Some("full"))?,
        _ => None,
    };

    let mut base_files: HashMap<String, FileManifestEntry> = HashMap::new();
    if let Some(ref ps) = parent_snap {
        for f in catalog.list_snapshot_files(&ps.id)? {
            base_files.insert(f.rel_path.clone(), f);
        }
    }

    // Resume existing interrupted snapshot or create a new in_progress checkpoint
    let (snap_id, mut already_done) = if resume {
        if let Some(in_prog) = catalog.find_in_progress(profile_name)? {
            let mut done = HashMap::new();
            for f in catalog.list_snapshot_files(&in_prog.id)? {
                done.insert(f.rel_path.clone(), f);
            }
            (in_prog.id, done)
        } else {
            let sid = make_snapshot_id();
            catalog.create_snapshot(&SnapshotRecord {
                id: sid.clone(),
                profile: profile_name.to_string(),
                mode: mode.to_string(),
                parent_id: parent_snap.as_ref().map(|p| p.id.clone()),
                status: "in_progress".to_string(),
                created_at: Utc::now().to_rfc3339(),
                total_files: 0,
                total_bytes: 0,
                new_chunks: 0,
                stored_bytes: 0,
            })?;
            (sid, HashMap::new())
        }
    } else {
        let sid = make_snapshot_id();
        catalog.create_snapshot(&SnapshotRecord {
            id: sid.clone(),
            profile: profile_name.to_string(),
            mode: mode.to_string(),
            parent_id: parent_snap.as_ref().map(|p| p.id.clone()),
            status: "in_progress".to_string(),
            created_at: Utc::now().to_rfc3339(),
            total_files: 0,
            total_bytes: 0,
            new_chunks: 0,
            stored_bytes: 0,
        })?;
        (sid, HashMap::new())
    };

    let mut total_files: i64 = 0;
    let mut total_bytes: i64 = 0;
    let mut new_chunks: i64 = 0;
    let mut stored_bytes: i64 = 0;

    for (src_idx, root) in effective_sources.iter().enumerate() {
        let root_abs = root
            .canonicalize()
            .map_err(|e| format!("source {}: {e}", root.display()))?;
        let src_prefix = if effective_sources.len() > 1 {
            format!("src{src_idx}_{}/", root_abs.file_name().and_then(|n| n.to_str()).unwrap_or("root"))
        } else {
            String::new()
        };

        for entry in WalkDir::new(&root_abs).into_iter().filter_map(Result::ok) {
            if !entry.file_type().is_file() {
                continue;
            }
            let rel_raw = entry
                .path()
                .strip_prefix(&root_abs)
                .map_err(|e| format!("strip prefix: {e}"))?;
            let rel_norm = format!("{}{}", src_prefix, rel_raw.to_string_lossy().replace('\\', "/"));
            if excl.is_match(&rel_norm) || excl.is_match(entry.file_name().to_string_lossy().as_ref()) {
                continue;
            }

            let meta = entry.metadata().map_err(|e| format!("metadata {rel_norm}: {e}"))?;
            let size_bytes = meta.len() as i64;
            let mtime_ns = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_nanos() as i64)
                .unwrap_or(0);

            total_files += 1;
            total_bytes += size_bytes;

            // If resuming and already recorded in this interrupted snapshot, reuse it!
            if already_done.contains_key(&rel_norm) {
                continue;
            }

            // Incremental / differential reuse when size + mtime match and chunks exist
            if let Some(prev) = base_files.get(&rel_norm) {
                if prev.size_bytes == size_bytes && prev.mtime_ns == mtime_ns {
                    let mut all_present = true;
                    for ch in &prev.chunk_hashes {
                        if !catalog.has_chunk(ch)? {
                            all_present = false;
                            break;
                        }
                    }
                    if all_present {
                        catalog.upsert_snapshot_file(&snap_id, prev)?;
                        already_done.insert(rel_norm, prev.clone());
                        continue;
                    }
                }
            }

            // Read and chunk file
            let mut file = File::open(entry.path()).map_err(|e| format!("open {rel_norm}: {e}"))?;
            let mut file_hasher = Sha256::new();
            let mut chunk_hashes = Vec::new();
            let mut buf = vec![0u8; manifest.chunk_size];

            loop {
                let n = read_full_chunk(&mut file, &mut buf)
                    .map_err(|e| format!("read {rel_norm}: {e}"))?;
                if n == 0 {
                    break;
                }
                let slice = &buf[..n];
                file_hasher.update(slice);
                let ch_hash = sha256_hex(slice);
                if !catalog.has_chunk(&ch_hash)? {
                    let sealed = seal_chunk(&key, &ch_hash, slice)?;
                    backend.put_chunk(&ch_hash, &sealed)?;
                    catalog.record_chunk(&ch_hash, n as i64, sealed.len() as i64)?;
                    new_chunks += 1;
                    stored_bytes += sealed.len() as i64;
                }
                chunk_hashes.push(ch_hash);
            }

            let fentry = FileManifestEntry {
                rel_path: rel_norm.clone(),
                size_bytes,
                mtime_ns,
                file_sha256: hex::encode(file_hasher.finalize()),
                chunk_hashes,
            };
            catalog.upsert_snapshot_file(&snap_id, &fentry)?;
            already_done.insert(rel_norm, fentry);
        }
    }

    catalog.finalize_snapshot(&snap_id, total_files, total_bytes, new_chunks, stored_bytes)?;
    catalog
        .get_snapshot(&snap_id)?
        .ok_or_else(|| "snapshot missing after finalize".to_string())
}

fn read_full_chunk<R: Read>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut read_total = 0;
    while read_total < buf.len() {
        let n = reader.read(&mut buf[read_total..])?;
        if n == 0 {
            break;
        }
        read_total += n;
    }
    Ok(read_total)
}

fn sanitize_rel_path(dest_root: &Path, rel: &str) -> Result<PathBuf, String> {
    let rel_path = Path::new(rel);
    let mut clean = PathBuf::new();
    for comp in rel_path.components() {
        match comp {
            Component::Normal(seg) => clean.push(seg),
            Component::CurDir => {}
            _ => return Err(format!("unsafe path component in snapshot: {rel}")),
        }
    }
    Ok(dest_root.join(clean))
}

pub fn restore_snapshot(
    repo_dir: &Path,
    passphrase: &str,
    s3_cfg: Option<S3Config>,
    snapshot_id: &str,
    dest_dir: &Path,
    filter_prefix: Option<&str>,
    dry_run: bool,
) -> Result<RestoreReport, String> {
    let (_manifest, key, catalog, backend) = open_repo(repo_dir, passphrase, s3_cfg)?;
    let _snap = catalog
        .get_snapshot(snapshot_id)?
        .ok_or_else(|| format!("snapshot {snapshot_id} not found"))?;
    let files = catalog.list_snapshot_files(snapshot_id)?;

    if !dry_run {
        fs::create_dir_all(dest_dir).map_err(|e| format!("create dest dir: {e}"))?;
    }

    let mut restored_files = Vec::new();
    let mut bytes_restored: u64 = 0;

    for f in files {
        if let Some(pref) = filter_prefix {
            if f.rel_path != pref && !f.rel_path.starts_with(pref) {
                continue;
            }
        }
        restored_files.push(f.rel_path.clone());
        bytes_restored += f.size_bytes as u64;
        if dry_run {
            continue;
        }

        let target = sanitize_rel_path(dest_dir, &f.rel_path)?;
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("mkdir restore parent: {e}"))?;
        }
        let mut out = File::create(&target).map_err(|e| format!("create {}: {e}", target.display()))?;
        let mut whole_hasher = Sha256::new();
        for ch in &f.chunk_hashes {
            let sealed = backend.get_chunk(ch)?;
            let plain = open_chunk(&key, ch, &sealed)?;
            whole_hasher.update(&plain);
            out.write_all(&plain).map_err(|e| format!("write restore: {e}"))?;
        }
        let actual_sha = hex::encode(whole_hasher.finalize());
        if actual_sha != f.file_sha256 {
            return Err(format!("restored file checksum mismatch for {}", f.rel_path));
        }
    }

    Ok(RestoreReport {
        snapshot_id: snapshot_id.to_string(),
        dry_run,
        files_restored: restored_files.len(),
        bytes_restored,
        files: restored_files,
    })
}

pub fn verify_repository(
    repo_dir: &Path,
    passphrase: &str,
    s3_cfg: Option<S3Config>,
) -> Result<VerifyReport, String> {
    let (_manifest, key, catalog, backend) = open_repo(repo_dir, passphrase, s3_cfg)?;
    let snaps = catalog.list_snapshots()?;
    let mut referenced: HashSet<String> = HashSet::new();
    let mut errors = Vec::new();

    for s in &snaps {
        for f in catalog.list_snapshot_files(&s.id)? {
            for h in f.chunk_hashes {
                referenced.insert(h);
            }
        }
    }

    for ch in &referenced {
        match backend.get_chunk(ch) {
            Ok(sealed) => {
                if let Err(e) = open_chunk(&key, ch, &sealed) {
                    errors.push(e);
                }
            }
            Err(e) => errors.push(format!("missing chunk {ch}: {e}")),
        }
    }

    Ok(VerifyReport {
        chunks_checked: referenced.len(),
        snapshots_checked: snaps.len(),
        healthy: errors.is_empty(),
        errors,
    })
}

pub fn prune_repository(
    repo_dir: &Path,
    passphrase: &str,
    s3_cfg: Option<S3Config>,
    keep_last: usize,
) -> Result<(usize, usize), String> {
    let (_manifest, _key, catalog, backend) = open_repo(repo_dir, passphrase, s3_cfg)?;
    let (removed_snaps, orphans) = catalog.delete_snapshot_and_gc(keep_last)?;
    for h in &orphans {
        backend.delete_chunk(h)?;
    }
    Ok((removed_snaps, orphans.len()))
}

pub fn stats_report(
    repo_dir: &Path,
    passphrase: &str,
    s3_cfg: Option<S3Config>,
) -> Result<RepoStatsReport, String> {
    let (_manifest, _key, catalog, _backend) = open_repo(repo_dir, passphrase, s3_cfg)?;
    let snaps = catalog.list_snapshots()?;
    let completed: Vec<_> = snaps.iter().filter(|s| s.status == "completed").collect();
    let total_logical: i64 = completed.iter().map(|s| s.total_bytes).sum();
    let chunks = catalog.all_chunks()?;
    let total_stored: i64 = chunks.iter().map(|(_, _, st)| *st).sum();
    let savings = if total_logical > 0 {
        ((total_logical as f64 - total_stored as f64) / total_logical as f64) * 100.0
    } else {
        0.0
    };
    Ok(RepoStatsReport {
        snapshots_total: snaps.len(),
        snapshots_completed: completed.len(),
        unique_chunks: chunks.len(),
        total_logical_bytes: total_logical,
        total_stored_bytes: total_stored,
        deduplication_savings_percent: (savings * 100.0).round() / 100.0,
    })
}
