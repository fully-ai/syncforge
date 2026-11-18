# SyncForge Architecture

1. **Crypto & Compression (`src/crypto.rs`)**: Derives a 256-bit repository key via PBKDF2-HMAC-SHA256 (`120,000` rounds), compresses each deduplicated chunk with Zstd, and seals it using AES-256-GCM with the chunk's plaintext SHA-256 hash bound as AAD.
2. **Storage Backends (`src/storage.rs`)**: Pluggable `StorageBackend` trait supporting local atomic fanout chunk files (`chunks/<prefix>/<hash>.blk`) and S3-compatible object storage signed via AWS Signature Version 4.
3. **Catalog & Snapshots (`src/catalog.rs`, `src/engine.rs`)**: SQLite (`rusqlite` WAL) tracks backup profiles, full/incremental/differential snapshots, `in_progress` checkpoints for `--resume`, file chunk manifests, retention pruning, orphan chunk GC, and cryptographic verification.
