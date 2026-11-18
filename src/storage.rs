use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

type HmacSha256 = Hmac<Sha256>;

pub trait StorageBackend: Send + Sync {
    fn put_chunk(&self, hash: &str, data: &[u8]) -> Result<(), String>;
    fn get_chunk(&self, hash: &str) -> Result<Vec<u8>, String>;
    fn has_chunk(&self, hash: &str) -> Result<bool, String>;
    fn delete_chunk(&self, hash: &str) -> Result<(), String>;
}

pub struct LocalBackend {
    chunks_dir: PathBuf,
}

impl LocalBackend {
    pub fn new(repo_root: &Path) -> Result<Self, String> {
        let chunks_dir = repo_root.join("chunks");
        fs::create_dir_all(&chunks_dir).map_err(|e| format!("create chunks dir: {e}"))?;
        Ok(Self { chunks_dir })
    }

    fn path_for(&self, hash: &str) -> PathBuf {
        let prefix = hash.get(0..2).unwrap_or("00");
        self.chunks_dir.join(prefix).join(format!("{hash}.blk"))
    }
}

impl StorageBackend for LocalBackend {
    fn put_chunk(&self, hash: &str, data: &[u8]) -> Result<(), String> {
        let p = self.path_for(hash);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("mkdir chunk prefix: {e}"))?;
        }
        let tmp = p.with_extension("tmp");
        fs::write(&tmp, data).map_err(|e| format!("write chunk tmp: {e}"))?;
        fs::rename(&tmp, &p).map_err(|e| format!("rename chunk: {e}"))?;
        Ok(())
    }

    fn get_chunk(&self, hash: &str) -> Result<Vec<u8>, String> {
        fs::read(self.path_for(hash)).map_err(|e| format!("read chunk {hash}: {e}"))
    }

    fn has_chunk(&self, hash: &str) -> Result<bool, String> {
        Ok(self.path_for(hash).is_file())
    }

    fn delete_chunk(&self, hash: &str) -> Result<(), String> {
        let p = self.path_for(hash);
        if p.exists() {
            fs::remove_file(p).map_err(|e| format!("delete chunk {hash}: {e}"))?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct S3Config {
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    pub access_key: String,
    pub secret_key: String,
}

/// S3-compatible HTTP object storage backend using AWS Signature Version 4.
pub struct S3Backend {
    cfg: S3Config,
    agent: ureq::Agent,
}

impl S3Backend {
    pub fn new(cfg: S3Config) -> Self {
        Self {
            cfg,
            agent: ureq::AgentBuilder::new().build(),
        }
    }

    fn object_key(hash: &str) -> String {
        let prefix = hash.get(0..2).unwrap_or("00");
        format!("chunks/{prefix}/{hash}.blk")
    }

    fn host_header(&self) -> String {
        self.cfg
            .endpoint
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/')
            .to_string()
    }

    fn object_url(&self, key: &str) -> String {
        format!(
            "{}/{}/{}",
            self.cfg.endpoint.trim_end_matches('/'),
            self.cfg.bucket,
            key
        )
    }

    fn sign_headers(&self, method: &str, key: &str, payload: &[u8]) -> (String, String, String) {
        let now = Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = now.format("%Y%m%d").to_string();
        let payload_hash = hex::encode(Sha256::digest(payload));
        let host = self.host_header();
        let canonical_uri = format!("/{}/{}", self.cfg.bucket, key);
        let canonical_headers = format!(
            "host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n"
        );
        let signed_headers = "host;x-amz-content-sha256;x-amz-date";
        let canonical_req = format!(
            "{method}\n{canonical_uri}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
        );

        let scope = format!("{date_stamp}/{}/s3/aws4_request", self.cfg.region);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
            hex::encode(Sha256::digest(canonical_req.as_bytes()))
        );

        let hmac_sha = |k: &[u8], msg: &[u8]| -> Vec<u8> {
            let mut m = HmacSha256::new_from_slice(k).expect("hmac key");
            m.update(msg);
            m.finalize().into_bytes().to_vec()
        };

        let k_date = hmac_sha(
            format!("AWS4{}", self.cfg.secret_key).as_bytes(),
            date_stamp.as_bytes(),
        );
        let k_region = hmac_sha(&k_date, self.cfg.region.as_bytes());
        let k_service = hmac_sha(&k_region, b"s3");
        let k_signing = hmac_sha(&k_service, b"aws4_request");
        let sig = hex::encode(hmac_sha(&k_signing, string_to_sign.as_bytes()));

        let auth = format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={sig}",
            self.cfg.access_key
        );
        (amz_date, payload_hash, auth)
    }
}

impl StorageBackend for S3Backend {
    fn put_chunk(&self, hash: &str, data: &[u8]) -> Result<(), String> {
        let key = Self::object_key(hash);
        let (amz_date, payload_hash, auth) = self.sign_headers("PUT", &key, data);
        self.agent
            .put(&self.object_url(&key))
            .set("x-amz-date", &amz_date)
            .set("x-amz-content-sha256", &payload_hash)
            .set("Authorization", &auth)
            .send_bytes(data)
            .map_err(|e| format!("S3 PUT {key}: {e}"))?;
        Ok(())
    }

    fn get_chunk(&self, hash: &str) -> Result<Vec<u8>, String> {
        let key = Self::object_key(hash);
        let (amz_date, payload_hash, auth) = self.sign_headers("GET", &key, &[]);
        let resp = self
            .agent
            .get(&self.object_url(&key))
            .set("x-amz-date", &amz_date)
            .set("x-amz-content-sha256", &payload_hash)
            .set("Authorization", &auth)
            .call()
            .map_err(|e| format!("S3 GET {key}: {e}"))?;
        let mut buf = Vec::new();
        resp.into_reader()
            .read_to_end(&mut buf)
            .map_err(|e| format!("S3 read {key}: {e}"))?;
        Ok(buf)
    }

    fn has_chunk(&self, hash: &str) -> Result<bool, String> {
        let key = Self::object_key(hash);
        let (amz_date, payload_hash, auth) = self.sign_headers("HEAD", &key, &[]);
        match self
            .agent
            .head(&self.object_url(&key))
            .set("x-amz-date", &amz_date)
            .set("x-amz-content-sha256", &payload_hash)
            .set("Authorization", &auth)
            .call()
        {
            Ok(_) => Ok(true),
            Err(ureq::Error::Status(404, _)) => Ok(false),
            Err(e) => Err(format!("S3 HEAD {key}: {e}")),
        }
    }

    fn delete_chunk(&self, hash: &str) -> Result<(), String> {
        let key = Self::object_key(hash);
        let (amz_date, payload_hash, auth) = self.sign_headers("DELETE", &key, &[]);
        match self
            .agent
            .delete(&self.object_url(&key))
            .set("x-amz-date", &amz_date)
            .set("x-amz-content-sha256", &payload_hash)
            .set("Authorization", &auth)
            .call()
        {
            Ok(_) | Err(ureq::Error::Status(404, _)) => Ok(()),
            Err(e) => Err(format!("S3 DELETE {key}: {e}")),
        }
    }
}
