use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotRecord {
    pub id: String,
    pub profile: String,
    pub mode: String,
    pub parent_id: Option<String>,
    pub status: String,
    pub created_at: String,
    pub total_files: i64,
    pub total_bytes: i64,
    pub new_chunks: i64,
    pub stored_bytes: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileManifestEntry {
    pub rel_path: String,
    pub size_bytes: i64,
    pub mtime_ns: i64,
    pub file_sha256: String,
    pub chunk_hashes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupProfile {
    pub name: String,
    pub sources: Vec<String>,
    pub excludes: Vec<String>,
    pub keep_last: usize,
}

pub struct Catalog {
    conn: Connection,
}

impl Catalog {
    pub fn open(db_path: &Path) -> Result<Self, String> {
        let conn = Connection::open(db_path).map_err(|e| format!("open catalog db: {e}"))?;
        conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA foreign_keys = ON;
            CREATE TABLE IF NOT EXISTS profiles (
                name TEXT PRIMARY KEY,
                sources_json TEXT NOT NULL,
                excludes_json TEXT NOT NULL,
                keep_last INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS snapshots (
                id TEXT PRIMARY KEY,
                profile TEXT NOT NULL,
                mode TEXT NOT NULL,
                parent_id TEXT,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                total_files INTEGER NOT NULL DEFAULT 0,
                total_bytes INTEGER NOT NULL DEFAULT 0,
                new_chunks INTEGER NOT NULL DEFAULT 0,
                stored_bytes INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS snapshot_files (
                snapshot_id TEXT NOT NULL,
                rel_path TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                mtime_ns INTEGER NOT NULL,
                file_sha256 TEXT NOT NULL,
                chunks_json TEXT NOT NULL,
                PRIMARY KEY (snapshot_id, rel_path),
                FOREIGN KEY (snapshot_id) REFERENCES snapshots(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS chunks (
                hash TEXT PRIMARY KEY,
                raw_size INTEGER NOT NULL,
                stored_size INTEGER NOT NULL
            );
            ",
        )
        .map_err(|e| format!("init catalog schema: {e}"))?;
        Ok(Self { conn })
    }

    pub fn upsert_profile(&self, p: &BackupProfile) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO profiles (name, sources_json, excludes_json, keep_last) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(name) DO UPDATE SET sources_json = excluded.sources_json, excludes_json = excluded.excludes_json, keep_last = excluded.keep_last",
                params![
                    p.name,
                    serde_json::to_string(&p.sources).unwrap_or_default(),
                    serde_json::to_string(&p.excludes).unwrap_or_default(),
                    p.keep_last as i64
                ],
            )
            .map_err(|e| format!("upsert profile: {e}"))?;
        Ok(())
    }

    pub fn get_profile(&self, name: &str) -> Result<Option<BackupProfile>, String> {
        self.conn
            .query_row(
                "SELECT name, sources_json, excludes_json, keep_last FROM profiles WHERE name = ?1",
                params![name],
                |row| {
                    let s_json: String = row.get(1)?;
                    let e_json: String = row.get(2)?;
                    let kl: i64 = row.get(3)?;
                    Ok(BackupProfile {
                        name: row.get(0)?,
                        sources: serde_json::from_str(&s_json).unwrap_or_default(),
                        excludes: serde_json::from_str(&e_json).unwrap_or_default(),
                        keep_last: kl as usize,
                    })
                },
            )
            .optional()
            .map_err(|e| format!("get profile: {e}"))
    }

    pub fn list_profiles(&self) -> Result<Vec<BackupProfile>, String> {
        let mut stmt = self
            .conn
            .prepare("SELECT name, sources_json, excludes_json, keep_last FROM profiles ORDER BY name ASC")
            .map_err(|e| format!("list profiles: {e}"))?;
        let rows = stmt
            .query_map([], |row| {
                let s_json: String = row.get(1)?;
                let e_json: String = row.get(2)?;
                let kl: i64 = row.get(3)?;
                Ok(BackupProfile {
                    name: row.get(0)?,
                    sources: serde_json::from_str(&s_json).unwrap_or_default(),
                    excludes: serde_json::from_str(&e_json).unwrap_or_default(),
                    keep_last: kl as usize,
                })
            })
            .map_err(|e| format!("query profiles: {e}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("collect profiles: {e}"))
    }

    pub fn create_snapshot(&self, rec: &SnapshotRecord) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO snapshots (id, profile, mode, parent_id, status, created_at, total_files, total_bytes, new_chunks, stored_bytes)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    rec.id,
                    rec.profile,
                    rec.mode,
                    rec.parent_id,
                    rec.status,
                    rec.created_at,
                    rec.total_files,
                    rec.total_bytes,
                    rec.new_chunks,
                    rec.stored_bytes
                ],
            )
            .map_err(|e| format!("create snapshot: {e}"))?;
        Ok(())
    }

    pub fn finalize_snapshot(
        &self,
        id: &str,
        total_files: i64,
        total_bytes: i64,
        new_chunks: i64,
        stored_bytes: i64,
    ) -> Result<(), String> {
        self.conn
            .execute(
                "UPDATE snapshots SET status = 'completed', total_files = ?2, total_bytes = ?3, new_chunks = ?4, stored_bytes = ?5 WHERE id = ?1",
                params![id, total_files, total_bytes, new_chunks, stored_bytes],
            )
            .map_err(|e| format!("finalize snapshot: {e}"))?;
        Ok(())
    }

    pub fn find_in_progress(&self, profile: &str) -> Result<Option<SnapshotRecord>, String> {
        self.conn
            .query_row(
                "SELECT id, profile, mode, parent_id, status, created_at, total_files, total_bytes, new_chunks, stored_bytes
                 FROM snapshots WHERE profile = ?1 AND status = 'in_progress' ORDER BY created_at DESC LIMIT 1",
                params![profile],
                Self::row_to_snap,
            )
            .optional()
            .map_err(|e| format!("find in_progress: {e}"))
    }

    pub fn latest_completed_snapshot(
        &self,
        profile: &str,
        mode_filter: Option<&str>,
    ) -> Result<Option<SnapshotRecord>, String> {
        let sql = if mode_filter.is_some() {
            "SELECT id, profile, mode, parent_id, status, created_at, total_files, total_bytes, new_chunks, stored_bytes
             FROM snapshots WHERE profile = ?1 AND status = 'completed' AND mode = ?2 ORDER BY created_at DESC LIMIT 1"
        } else {
            "SELECT id, profile, mode, parent_id, status, created_at, total_files, total_bytes, new_chunks, stored_bytes
             FROM snapshots WHERE profile = ?1 AND status = 'completed' ORDER BY created_at DESC LIMIT 1"
        };
        let res = if let Some(m) = mode_filter {
            self.conn.query_row(sql, params![profile, m], Self::row_to_snap)
        } else {
            self.conn.query_row(sql, params![profile], Self::row_to_snap)
        };
        res.optional().map_err(|e| format!("latest completed: {e}"))
    }

    pub fn get_snapshot(&self, id: &str) -> Result<Option<SnapshotRecord>, String> {
        self.conn
            .query_row(
                "SELECT id, profile, mode, parent_id, status, created_at, total_files, total_bytes, new_chunks, stored_bytes
                 FROM snapshots WHERE id = ?1",
                params![id],
                Self::row_to_snap,
            )
            .optional()
            .map_err(|e| format!("get snapshot: {e}"))
    }

    pub fn list_snapshots(&self) -> Result<Vec<SnapshotRecord>, String> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, profile, mode, parent_id, status, created_at, total_files, total_bytes, new_chunks, stored_bytes FROM snapshots ORDER BY created_at DESC")
            .map_err(|e| format!("list snapshots: {e}"))?;
        let rows = stmt
            .query_map([], Self::row_to_snap)
            .map_err(|e| format!("query snapshots: {e}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("collect snapshots: {e}"))
    }

    fn row_to_snap(row: &rusqlite::Row<'_>) -> rusqlite::Result<SnapshotRecord> {
        Ok(SnapshotRecord {
            id: row.get(0)?,
            profile: row.get(1)?,
            mode: row.get(2)?,
            parent_id: row.get(3)?,
            status: row.get(4)?,
            created_at: row.get(5)?,
            total_files: row.get(6)?,
            total_bytes: row.get(7)?,
            new_chunks: row.get(8)?,
            stored_bytes: row.get(9)?,
        })
    }

    pub fn upsert_snapshot_file(&self, snap_id: &str, f: &FileManifestEntry) -> Result<(), String> {
        let chunks_json = serde_json::to_string(&f.chunk_hashes).unwrap_or_default();
        self.conn
            .execute(
                "INSERT INTO snapshot_files (snapshot_id, rel_path, size_bytes, mtime_ns, file_sha256, chunks_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(snapshot_id, rel_path) DO UPDATE SET size_bytes=excluded.size_bytes, mtime_ns=excluded.mtime_ns, file_sha256=excluded.file_sha256, chunks_json=excluded.chunks_json",
                params![snap_id, f.rel_path, f.size_bytes, f.mtime_ns, f.file_sha256, chunks_json],
            )
            .map_err(|e| format!("upsert snapshot file: {e}"))?;
        Ok(())
    }

    pub fn list_snapshot_files(&self, snap_id: &str) -> Result<Vec<FileManifestEntry>, String> {
        let mut stmt = self
            .conn
            .prepare("SELECT rel_path, size_bytes, mtime_ns, file_sha256, chunks_json FROM snapshot_files WHERE snapshot_id = ?1 ORDER BY rel_path ASC")
            .map_err(|e| format!("list snapshot files: {e}"))?;
        let rows = stmt
            .query_map(params![snap_id], |row| {
                let cjson: String = row.get(4)?;
                Ok(FileManifestEntry {
                    rel_path: row.get(0)?,
                    size_bytes: row.get(1)?,
                    mtime_ns: row.get(2)?,
                    file_sha256: row.get(3)?,
                    chunk_hashes: serde_json::from_str(&cjson).unwrap_or_default(),
                })
            })
            .map_err(|e| format!("query snapshot files: {e}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("collect snapshot files: {e}"))
    }

    pub fn has_chunk(&self, hash: &str) -> Result<bool, String> {
        let found: Option<i64> = self
            .conn
            .query_row("SELECT 1 FROM chunks WHERE hash = ?1", params![hash], |r| r.get(0))
            .optional()
            .map_err(|e| format!("check chunk: {e}"))?;
        Ok(found.is_some())
    }

    pub fn record_chunk(&self, hash: &str, raw_size: i64, stored_size: i64) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO chunks (hash, raw_size, stored_size) VALUES (?1, ?2, ?3)",
                params![hash, raw_size, stored_size],
            )
            .map_err(|e| format!("record chunk: {e}"))?;
        Ok(())
    }

    pub fn all_chunks(&self) -> Result<Vec<(String, i64, i64)>, String> {
        let mut stmt = self
            .conn
            .prepare("SELECT hash, raw_size, stored_size FROM chunks")
            .map_err(|e| format!("list chunks: {e}"))?;
        let rows = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .map_err(|e| format!("query chunks: {e}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("collect chunks: {e}"))
    }

    pub fn delete_snapshot_and_gc(&self, keep_last: usize) -> Result<(usize, Vec<String>), String> {
        let snaps = self.list_snapshots()?;
        let completed: Vec<_> = snaps.into_iter().filter(|s| s.status == "completed").collect();
        if completed.len() <= keep_last {
            return Ok((0, Vec::new()));
        }
        let to_remove = &completed[keep_last..];
        for s in to_remove {
            self.conn
                .execute("DELETE FROM snapshots WHERE id = ?1", params![s.id])
                .map_err(|e| format!("delete snapshot {}: {e}", s.id))?;
        }

        // Compute referenced chunk set across remaining snapshots
        let mut referenced: HashMap<String, bool> = HashMap::new();
        for s in self.list_snapshots()? {
            for f in self.list_snapshot_files(&s.id)? {
                for h in f.chunk_hashes {
                    referenced.insert(h, true);
                }
            }
        }
        let mut orphan_hashes = Vec::new();
        for (h, _, _) in self.all_chunks()? {
            if !referenced.contains_key(&h) {
                orphan_hashes.push(h);
            }
        }
        for h in &orphan_hashes {
            self.conn
                .execute("DELETE FROM chunks WHERE hash = ?1", params![h])
                .map_err(|e| format!("delete orphan chunk {h}: {e}"))?;
        }
        Ok((to_remove.len(), orphan_hashes))
    }
}
