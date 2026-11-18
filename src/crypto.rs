use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const KDF_ITERATIONS: u32 = 120_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoManifest {
    pub version: u32,
    pub salt_hex: String,
    pub kdf_iterations: u32,
    pub chunk_size: usize,
    pub key_check_hex: String,
}

pub fn derive_key(passphrase: &str, salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), salt, iterations, &mut key);
    key
}

pub fn key_fingerprint(key: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"syncforge-key-check:");
    hasher.update(key);
    hex::encode(hasher.finalize())
}

pub fn create_manifest(passphrase: &str, chunk_size: usize) -> (RepoManifest, [u8; 32]) {
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let key = derive_key(passphrase, &salt, KDF_ITERATIONS);
    let manifest = RepoManifest {
        version: 1,
        salt_hex: hex::encode(salt),
        kdf_iterations: KDF_ITERATIONS,
        chunk_size,
        key_check_hex: key_fingerprint(&key),
    };
    (manifest, key)
}

pub fn unlock_manifest(manifest: &RepoManifest, passphrase: &str) -> Result<[u8; 32], String> {
    let salt = hex::decode(&manifest.salt_hex).map_err(|e| format!("invalid salt: {e}"))?;
    let key = derive_key(passphrase, &salt, manifest.kdf_iterations);
    if key_fingerprint(&key) != manifest.key_check_hex {
        return Err("invalid repository passphrase".to_string());
    }
    Ok(key)
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// Compresses plaintext with Zstd and encrypts via AES-256-GCM binding chunk_hash as AAD.
pub fn seal_chunk(key: &[u8; 32], chunk_hash: &str, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let compressed =
        zstd::bulk::compress(plaintext, 3).map_err(|e| format!("zstd compress failed: {e}"))?;
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("cipher init: {e}"))?;
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: &compressed,
                aad: chunk_hash.as_bytes(),
            },
        )
        .map_err(|e| format!("aead encrypt failed: {e}"))?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn open_chunk(key: &[u8; 32], chunk_hash: &str, sealed: &[u8]) -> Result<Vec<u8>, String> {
    if sealed.len() < 13 {
        return Err("corrupted chunk: too short".to_string());
    }
    let (nonce_bytes, ct) = sealed.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("cipher init: {e}"))?;
    let compressed = cipher
        .decrypt(
            Nonce::from_slice(nonce_bytes),
            Payload {
                msg: ct,
                aad: chunk_hash.as_bytes(),
            },
        )
        .map_err(|_| format!("AEAD authentication failed for chunk {chunk_hash}"))?;
    let plain = zstd::stream::decode_all(compressed.as_slice())
        .map_err(|e| format!("zstd decompress failed: {e}"))?;
    if sha256_hex(&plain) != chunk_hash {
        return Err(format!("SHA-256 digest mismatch for chunk {chunk_hash}"));
    }
    Ok(plain)
}
