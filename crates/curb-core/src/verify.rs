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
    /// True only if Windows verified the full certificate trust chain (`WinVerifyTrust`).
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

/// Inspects an executable: computes SHA-256 and, on Windows, verifies its
/// Authenticode signature (`WinVerifyTrust`) and extracts certificate & PE metadata.
///
/// Results are cached in-memory keyed by `(lowercased path, file size, mtime)`.
pub fn inspect_binary(path: &Path) -> Result<BinaryIdentity> {
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

    #[cfg(windows)]
    let (signature, product_name, original_filename, file_description) =
        windows_impl::inspect_authenticode_and_pe(path);

    #[cfg(not(windows))]
    let (signature, product_name, original_filename, file_description) = (None, None, None, None);

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

/// Fast, non-hashing metadata inspection for listing many executables (running
/// processes or installed Steam games) without stalling on full-file SHA-256
/// reads or `WinVerifyTrust`.
///
/// If the file has already been fully verified via `inspect_binary`, the full
/// cached `BinaryIdentity` (with `sha256` and `WinVerifyTrust` result) is
/// returned immediately. Otherwise `sha256` is empty and only the embedded
/// signer certificate metadata (if any) is read. Callers must perform a full
/// `inspect_binary` before persisting a security rule when `sha256` is empty.
pub fn peek_binary(path: &Path) -> Result<BinaryIdentity> {
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

    #[cfg(windows)]
    let signature = windows_impl::peek_authenticode_signer(path);

    #[cfg(not(windows))]
    let signature = None;

    let identity = BinaryIdentity {
        path: path.to_string_lossy().to_string(),
        filename,
        sha256: String::new(),
        signature,
        product_name: None,
        original_filename: None,
        file_description: None,
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

#[cfg(windows)]
mod windows_impl {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr;

    use windows::core::{GUID, PCWSTR};
    use windows::Win32::Foundation::HWND;
    use windows::Win32::Security::Cryptography::{
        CertCloseStore, CertFindCertificateInStore, CertFreeCertificateContext,
        CertGetNameStringW, CryptMsgClose, CryptMsgGetParam, CryptQueryObject, CERT_CONTEXT,
        CERT_FIND_SUBJECT_CERT, CERT_INFO, CERT_NAME_SIMPLE_DISPLAY_TYPE,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_FLAG_BINARY,
        CERT_QUERY_OBJECT_FILE, CMSG_SIGNER_INFO, CMSG_SIGNER_INFO_PARAM, HCERTSTORE,
        PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
    };
    use windows::Win32::Security::WinTrust::{
        WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0,
        WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE,
        WTD_REVOCATION_CHECK_NONE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE,
        WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    };

    use super::SignatureInfo;

    pub fn inspect_authenticode_and_pe(
        path: &Path,
    ) -> (Option<SignatureInfo>, Option<String>, Option<String>, Option<String>) {
        let wide: Vec<u16> = OsStr::new(path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let trusted = verify_wintrust(&wide);
        let signature = read_signer_certificate(&wide, trusted);

        // PE version info can be added via GetFileVersionInfoW; keep filename fallback clean for now.
        (signature, None, None, None)
    }

    pub fn peek_authenticode_signer(path: &Path) -> Option<SignatureInfo> {
        let wide: Vec<u16> = OsStr::new(path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        read_signer_certificate(&wide, false)
    }

    fn verify_wintrust(wide_path: &[u16]) -> bool {
        let mut file_info = WINTRUST_FILE_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: PCWSTR(wide_path.as_ptr()),
            hFile: Default::default(),
            pgKnownSubject: ptr::null_mut(),
        };

        let mut data = WINTRUST_DATA {
            cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_NONE,
            dwUnionChoice: WTD_CHOICE_FILE,
            Anonymous: WINTRUST_DATA_0 {
                pFile: &mut file_info,
            },
            dwStateAction: WTD_STATEACTION_VERIFY,
            // Never perform network AIA/CRL/OCSP/CTL fetches; Curb blocks outbound
            // internet by default, so online URL retrieval causes multi-second hangs.
            dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE,
            ..Default::default()
        };

        let no_ui_hwnd = HWND(-1isize as *mut _);
        let mut action: GUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let status = unsafe {
            WinVerifyTrust(
                no_ui_hwnd,
                &mut action,
                &mut data as *mut _ as *mut _,
            )
        };

        data.dwStateAction = WTD_STATEACTION_CLOSE;
        unsafe {
            let _ = WinVerifyTrust(
                no_ui_hwnd,
                &mut action,
                &mut data as *mut _ as *mut _,
            );
        }

        status == 0
    }

    fn read_signer_certificate(wide_path: &[u16], trusted: bool) -> Option<SignatureInfo> {
        let mut encoding = Default::default();
        let mut content_type = Default::default();
        let mut format_type = Default::default();
        let mut store = HCERTSTORE::default();
        let mut msg: *mut std::ffi::c_void = ptr::null_mut();

        let ok = unsafe {
            CryptQueryObject(
                CERT_QUERY_OBJECT_FILE,
                wide_path.as_ptr() as *const _,
                CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                CERT_QUERY_FORMAT_FLAG_BINARY,
                0,
                Some(&mut encoding),
                Some(&mut content_type),
                Some(&mut format_type),
                Some(&mut store),
                Some(&mut msg),
                None,
            )
        };
        if ok.is_err() || msg.is_null() {
            return None;
        }

        let result = unsafe { extract_signer_from_msg(store, msg, trusted) };

        unsafe {
            let _ = CryptMsgClose(Some(msg));
            if !store.is_invalid() {
                let _ = CertCloseStore(store, 0);
            }
        }
        result
    }

    unsafe fn extract_signer_from_msg(
        store: HCERTSTORE,
        msg: *const std::ffi::c_void,
        trusted: bool,
    ) -> Option<SignatureInfo> {
        let mut size = 0u32;
        if CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, None, &mut size).is_err() || size == 0 {
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        if CryptMsgGetParam(
            msg,
            CMSG_SIGNER_INFO_PARAM,
            0,
            Some(buf.as_mut_ptr() as *mut _),
            &mut size,
        )
        .is_err()
        {
            return None;
        }

        let signer_info = &*(buf.as_ptr() as *const CMSG_SIGNER_INFO);
        let cert_info = CERT_INFO {
            Issuer: signer_info.Issuer,
            SerialNumber: signer_info.SerialNumber,
            ..Default::default()
        };

        let cert: *const CERT_CONTEXT = CertFindCertificateInStore(
            store,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_SUBJECT_CERT,
            Some(&cert_info as *const _ as *const _),
            None,
        );
        if cert.is_null() {
            return None;
        }

        let subject_cn = cert_name(cert, 0);
        let issuer_cn = cert_name(cert, 1); // CERT_NAME_ISSUER_FLAG = 1
        let _ = CertFreeCertificateContext(Some(cert));

        Some(SignatureInfo {
            trusted,
            subject_cn,
            issuer_cn,
        })
    }

    unsafe fn cert_name(cert: *const CERT_CONTEXT, flags: u32) -> String {
        let mut buf = [0u16; 256];
        let len = CertGetNameStringW(
            cert,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            flags,
            None,
            Some(&mut buf),
        );
        if len > 1 {
            String::from_utf16_lossy(&buf[..(len as usize - 1)])
        } else {
            String::new()
        }
    }
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

        // Once fully inspected, peek_binary should return the full cached identity.
        let peeked_cached = peek_binary(&tmp).unwrap();
        assert_eq!(peeked_cached.sha256, full.sha256);

        let _ = std::fs::remove_file(&tmp);
    }
}
