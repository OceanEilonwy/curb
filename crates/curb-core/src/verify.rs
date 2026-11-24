use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::{OnceLock, RwLock};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::Result;

type CacheKey = (String, u64, SystemTime);
const MAX_CACHE_ENTRIES: usize = 4096;

/// OS-specific metadata tuple extracted by a `BinaryVerifier` adaptor:
/// `(signature, product_name, original_filename, file_description)`.
pub type BinaryMetadata = (
    Option<SignatureInfo>,
    Option<String>,
    Option<String>,
    Option<String>,
);

fn full_inspect_cache() -> &'static RwLock<HashMap<CacheKey, BinaryIdentity>> {
    static CACHE: OnceLock<RwLock<HashMap<CacheKey, BinaryIdentity>>> = OnceLock::new();
    CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

fn peek_inspect_cache() -> &'static RwLock<HashMap<CacheKey, BinaryIdentity>> {
    static CACHE: OnceLock<RwLock<HashMap<CacheKey, BinaryIdentity>>> = OnceLock::new();
    CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

fn cache_key(path: &Path) -> Option<CacheKey> {
    let meta = std::fs::metadata(path).ok()?;
    let modified = meta.modified().ok()?;
    Some((
        path.to_string_lossy().to_ascii_lowercase(),
        meta.len(),
        modified,
    ))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignatureInfo {
    /// True only if the OS verified the full certificate trust chain.
    pub trusted: bool,
    /// Certificate subject common name (e.g. `"Valve Corp."`).
    pub subject_cn: String,
    /// Certificate issuer common name (e.g. `"DigiCert Trusted G4"`).
    pub issuer_cn: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BinaryIdentity {
    pub path: String,
    pub filename: String,
    pub sha256: String,
    pub signature: Option<SignatureInfo>,
    pub product_name: Option<String>,
    pub original_filename: Option<String>,
    pub file_description: Option<String>,
}

/// Computes the lowercase hex SHA-256 digest of a file on disk.
pub fn compute_sha256(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
}

/// Inspects an executable with a caller-supplied OS metadata extractor (`inspect_meta`)
/// and caches the result by `(lowercased path, file size, mtime)`.
pub fn inspect_binary_with<F>(path: &Path, inspect_meta: F) -> Result<BinaryIdentity>
where
    F: FnOnce(&Path) -> BinaryMetadata,
{
    let key = cache_key(path);
    if let Some(ref k) = key {
        if let Ok(cache) = full_inspect_cache().read() {
            if let Some(cached) = cache.get(k) {
                return Ok(cached.clone());
            }
        }
    }

    let sha256 = compute_sha256(path)?;
    let filename = path
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_default();

    let (signature, product_name, original_filename, file_description) = inspect_meta(path);

    let identity = BinaryIdentity {
        path: path.to_string_lossy().to_string(),
        filename,
        sha256,
        signature,
        product_name,
        original_filename,
        file_description,
    };

    if let Some(k) = key {
        if let Ok(mut cache) = full_inspect_cache().write() {
            if cache.len() >= MAX_CACHE_ENTRIES {
                cache.clear();
            }
            cache.insert(k, identity.clone());
        }
    }

    Ok(identity)
}

/// Pure-Rust binary inspection (computes SHA-256 without OS signature verification).
pub fn inspect_binary(path: &Path) -> Result<BinaryIdentity> {
    inspect_binary_with(path, |_| (None, None, None, None))
}

/// Fast, non-hashing metadata inspection with a caller-supplied OS metadata extractor.
/// Reuses the full inspection cache if the file was already verified.
pub fn peek_binary_with<F>(path: &Path, peek_meta: F) -> Result<BinaryIdentity>
where
    F: FnOnce(&Path) -> BinaryMetadata,
{
    let meta = std::fs::metadata(path)?;
    let key = meta
        .modified()
        .ok()
        .map(|m| (path.to_string_lossy().to_ascii_lowercase(), meta.len(), m));

    if let Some(ref k) = key {
        if let Ok(cache) = full_inspect_cache().read() {
            if let Some(cached) = cache.get(k) {
                return Ok(cached.clone());
            }
        }
        if let Ok(cache) = peek_inspect_cache().read() {
            if let Some(cached) = cache.get(k) {
                return Ok(cached.clone());
            }
        }
    }

    let filename = path
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_default();

    let (signature, product_name, original_filename, file_description) = peek_meta(path);

    let identity = BinaryIdentity {
        path: path.to_string_lossy().to_string(),
        filename,
        sha256: String::new(),
        signature,
        product_name,
        original_filename,
        file_description,
    };

    if let Some(k) = key {
        if let Ok(mut cache) = peek_inspect_cache().write() {
            if cache.len() >= MAX_CACHE_ENTRIES {
                cache.clear();
            }
            cache.insert(k, identity.clone());
        }
    }

    Ok(identity)
}

/// Pure-Rust metadata-only peek (skips hashing and OS signature verification).
pub fn peek_binary(path: &Path) -> Result<BinaryIdentity> {
    peek_binary_with(path, |_| (None, None, None, None))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn computes_known_sha256() {
        let tmp = std::env::temp_dir().join(format!("curb_sha_{}", uuid::Uuid::new_v4()));
        std::fs::write(&tmp, b"abc").unwrap();
        let identity = inspect_binary(&tmp).unwrap();
        assert_eq!(
            identity.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn peek_skips_hashing_and_reuses_full_cache() {
        let tmp = std::env::temp_dir().join(format!("curb_peek_{}.exe", uuid::Uuid::new_v4()));
        std::fs::write(&tmp, b"abc").unwrap();

        let peeked = peek_binary(&tmp).unwrap();
        assert!(peeked.sha256.is_empty());
        assert_eq!(
            peeked.filename,
            tmp.file_name().unwrap().to_string_lossy()
        );

        let full = inspect_binary(&tmp).unwrap();
        assert_eq!(
            full.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );

        let peeked_cached = peek_binary(&tmp).unwrap();
        assert_eq!(peeked_cached.sha256, full.sha256);

        let _ = std::fs::remove_file(&tmp);
    }
}
