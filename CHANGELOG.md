# Changelog

## [0.1.0] - 2026-11-18

### Added
- Content-addressed chunk store with configurable chunk sizing, SHA-256 deduplication, Zstd compression, and AES-256-GCM AEAD encryption (with SHA-256 AAD binding and PBKDF2-HMAC-SHA256 key derivation).
- SQLite catalog (`catalog.db`) supporting backup profiles, full/incremental/differential snapshots, multi-source roots, glob exclusion patterns, and interrupted backup resume checkpoints.
- Storage backends for local fanout directories (`local://` / path) and S3-compatible object storage using AWS Signature Version 4 (`HMAC-SHA256`).
- Full snapshot restore, individual file/prefix restore, `--dry-run` restore previews, deep cryptographic `verify`, `prune` retention policies with unreferenced chunk GC, JSON health/storage reports, and scheduled `daemon` background mode.
