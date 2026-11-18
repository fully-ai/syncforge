# Security Policy

## Reporting a Vulnerability

Please report cryptographic or storage security issues responsibly via GitHub Security Advisories without disclosing exploit vectors before a fix is published.

## Cryptography & Integrity Guarantees

1. **Key Derivation:** Repository master keys (`32 bytes`) are derived from the user passphrase and a random per-repository `16-byte` salt stored in `repo.json` using PBKDF2-HMAC-SHA256 (`120,000` iterations).
2. **Authenticated Chunk Encryption:** Every deduplicated chunk is compressed with Zstandard (`zstd`) and encrypted with **AES-256-GCM** using a unique `96-bit` random nonce per chunk and the chunk's plaintext SHA-256 hash bound as Authenticated Additional Data (AAD). Any ciphertext bit-flip or chunk-substitution attack fails AEAD tag authentication during `restore` or `verify`.
3. **Path Traversal Protection on Restore:** Restoring snapshots rejects `..` parent components and normalizes relative file paths inside the destination directory.
