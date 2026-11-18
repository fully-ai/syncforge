use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;
use syncforge::catalog::Catalog;
use syncforge::engine::{
    init_repository, open_repo, prune_repository, restore_snapshot, run_backup, stats_report,
    verify_repository,
};
use syncforge::storage::S3Config;
use tempfile::TempDir;

#[test]
fn test_encrypted_dedup_incremental_restore_verify_and_prune() {
    let tmp = TempDir::new().unwrap();
    let repo_dir = tmp.path().join("vault");
    let src1 = tmp.path().join("src1");
    let src2 = tmp.path().join("src2");
    fs::create_dir_all(src1.join("nested")).unwrap();
    fs::create_dir_all(&src2).unwrap();

    // Repetitive 30KB blocks exercise both Zstd compression and chunk deduplication across copies
    let payload_a = vec![b'A'; 20_000];
    let mut payload_b = vec![b'B'; 12_000];
    payload_b.extend_from_slice(&[b'C'; 4_000]);

    fs::write(src1.join("a.bin"), &payload_a).unwrap();
    fs::write(src1.join("nested/dup.bin"), &payload_a).unwrap(); // identical content -> deduplicated
    fs::write(src1.join("ignored.tmp"), b"skip me").unwrap();
    fs::write(src2.join("b.bin"), &payload_b).unwrap();

    init_repository(&repo_dir, "super-secret-pass", 8192).unwrap();

    // Wrong passphrase must fail cleanly
    assert!(open_repo(&repo_dir, "wrong-pass", None).is_err());

    // 1. Full backup across 2 sources with exclusion glob
    let snap1 = run_backup(
        &repo_dir,
        "super-secret-pass",
        None,
        "prod",
        &[src1.clone(), src2.clone()],
        &["*.tmp".to_string()],
        "full",
        false,
    )
    .unwrap();
    assert_eq!(snap1.total_files, 3);
    assert_eq!(snap1.status, "completed");

    // 2. Incremental backup with no edits uploads 0 new chunks
    let snap2 = run_backup(
        &repo_dir,
        "super-secret-pass",
        None,
        "prod",
        &[],
        &["*.tmp".to_string()],
        "incremental",
        false,
    )
    .unwrap();
    assert_eq!(snap2.new_chunks, 0);

    // 3. Dry-run preview + full restore + single-file restore
    let restore_dir = tmp.path().join("restored");
    let preview = restore_snapshot(
        &repo_dir,
        "super-secret-pass",
        None,
        &snap1.id,
        &restore_dir,
        None,
        true,
    )
    .unwrap();
    assert_eq!(preview.files_restored, 3);
    assert!(!restore_dir.exists());

    let full = restore_snapshot(
        &repo_dir,
        "super-secret-pass",
        None,
        &snap1.id,
        &restore_dir,
        None,
        false,
    )
    .unwrap();
    assert_eq!(full.files_restored, 3);
    assert_eq!(
        fs::read(restore_dir.join("src0_src1/a.bin")).unwrap(),
        payload_a
    );
    assert_eq!(
        fs::read(restore_dir.join("src1_src2/b.bin")).unwrap(),
        payload_b
    );
    assert!(!restore_dir.join("src0_src1/ignored.tmp").exists());

    // Single file restore
    let single_dir = tmp.path().join("single");
    let single = restore_snapshot(
        &repo_dir,
        "super-secret-pass",
        None,
        &snap1.id,
        &single_dir,
        Some("src1_src2/b.bin"),
        false,
    )
    .unwrap();
    assert_eq!(single.files_restored, 1);
    assert_eq!(fs::read(single_dir.join("src1_src2/b.bin")).unwrap(), payload_b);

    // 4. Verify integrity passes before tampering
    let v_ok = verify_repository(&repo_dir, "super-secret-pass", None).unwrap();
    assert!(v_ok.healthy);
    assert!(v_ok.chunks_checked >= 2);

    // Stats report shows dedup/compression savings
    let stats = stats_report(&repo_dir, "super-secret-pass", None).unwrap();
    assert!(stats.deduplication_savings_percent > 50.0);

    // 5. Prune oldest snapshot and add differential after modifying one file
    fs::write(src1.join("c.bin"), b"fresh differential data").unwrap();
    let snap3 = run_backup(
        &repo_dir,
        "super-secret-pass",
        None,
        "prod",
        &[],
        &["*.tmp".to_string()],
        "differential",
        false,
    )
    .unwrap();
    assert!(snap3.new_chunks >= 1);

    let (removed_snaps, _orphans) = prune_repository(&repo_dir, "super-secret-pass", None, 1).unwrap();
    assert_eq!(removed_snaps, 2);

    // 6. Bit-flip tampering on stored chunk must fail AEAD verification
    let cat = Catalog::open(&repo_dir.join("catalog.db")).unwrap();
    let (hash, _, _) = cat.all_chunks().unwrap().into_iter().next().unwrap();
    let chunk_path = repo_dir.join("chunks").join(&hash[0..2]).join(format!("{hash}.blk"));
    let mut raw = fs::read(&chunk_path).unwrap();
    let last = raw.len() - 1;
    raw[last] ^= 0xFF;
    fs::write(&chunk_path, raw).unwrap();

    let v_bad = verify_repository(&repo_dir, "super-secret-pass", None).unwrap();
    assert!(!v_bad.healthy);
    assert!(!v_bad.errors.is_empty());
}

#[test]
fn test_s3_compatible_sigv4_backend_roundtrip() {
    // Minimal HTTP server validating AWS4-HMAC-SHA256 header presence and storing PUT/GET/HEAD/DELETE objects
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let objects: Arc<Mutex<HashMap<String, Vec<u8>>>> = Arc::new(Mutex::new(HashMap::new()));
    let store_ref = objects.clone();

    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let store = store_ref.clone();
            thread::spawn(move || handle_s3_http(stream, store));
        }
    });

    let tmp = TempDir::new().unwrap();
    let repo_dir = tmp.path().join("s3_repo");
    let src = tmp.path().join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("secret.txt"), b"hello s3 vault").unwrap();

    init_repository(&repo_dir, "s3-passphrase", 4096).unwrap();
    let s3_cfg = S3Config {
        endpoint: format!("http://{addr}"),
        bucket: "backups".to_string(),
        region: "us-east-1".to_string(),
        access_key: "testkey".to_string(),
        secret_key: "testsecret".to_string(),
    };

    let snap = run_backup(
        &repo_dir,
        "s3-passphrase",
        Some(s3_cfg.clone()),
        "s3prof",
        &[src],
        &[],
        "full",
        false,
    )
    .unwrap();
    assert!(snap.new_chunks >= 1);
    assert_eq!(objects.lock().unwrap().len(), snap.new_chunks as usize);

    let out = tmp.path().join("out");
    let rst = restore_snapshot(
        &repo_dir,
        "s3-passphrase",
        Some(s3_cfg),
        &snap.id,
        &out,
        None,
        false,
    )
    .unwrap();
    assert_eq!(rst.files_restored, 1);
    assert_eq!(fs::read(out.join("secret.txt")).unwrap(), b"hello s3 vault");
}

fn handle_s3_http(mut stream: std::net::TcpStream, store: Arc<Mutex<HashMap<String, Vec<u8>>>>) {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let mut hdr_end = None;
    while hdr_end.is_none() {
        let Ok(n) = stream.read(&mut tmp) else { return; };
        if n == 0 {
            return;
        }
        buf.extend_from_slice(&tmp[..n]);
        hdr_end = buf.windows(4).position(|w| w == b"\r\n\r\n");
    }
    let he = hdr_end.unwrap();
    let hdr_str = String::from_utf8_lossy(&buf[..he]).to_string();
    let mut lines = hdr_str.lines();
    let first = lines.next().unwrap_or("");
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("").to_string();

    let mut content_len = 0usize;
    let mut has_sigv4 = false;
    for l in lines {
        let low = l.to_ascii_lowercase();
        if low.starts_with("content-length:") {
            content_len = l.split(':').nth(1).unwrap_or("0").trim().parse().unwrap_or(0);
        }
        if low.starts_with("authorization:") && l.contains("AWS4-HMAC-SHA256") {
            has_sigv4 = true;
        }
    }

    let mut body = buf[(he + 4)..].to_vec();
    while body.len() < content_len {
        let Ok(n) = stream.read(&mut tmp) else { break; };
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(content_len);

    if !has_sigv4 {
        let _ = stream.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        return;
    }

    let mut map = store.lock().unwrap();
    match method {
        "PUT" => {
            map.insert(path, body);
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        }
        "GET" => {
            if let Some(data) = map.get(&path) {
                let hdr = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", data.len());
                let _ = stream.write_all(hdr.as_bytes());
                let _ = stream.write_all(data);
            } else {
                let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            }
        }
        "HEAD" => {
            if map.contains_key(&path) {
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            } else {
                let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            }
        }
        "DELETE" => {
            map.remove(&path);
            let _ = stream.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        }
        _ => {
            let _ = stream.write_all(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        }
    }
}
