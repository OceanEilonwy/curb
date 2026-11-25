use curb_core::sync::{
    backup_slot_id, backup_write_signature, decrypt_sync_bundle, encrypt_sync_bundle, SyncBundle,
};

use crate::{P2pError, Result};

/// Uploads an E2E-encrypted [`SyncBundle`] to `curb-relay`'s optional backup slot.
///
/// The relay server never sees the plaintext config, admin list, or group key—only
/// the opaque BLAKE3 slot ID and XChaCha20-Poly1305 ciphertext.
pub async fn upload_encrypted_backup(
    relay_url: &str,
    group_key: &[u8; 32],
    bundle: &SyncBundle,
) -> Result<()> {
    let base = relay_url.trim_end_matches('/');
    if base.is_empty() {
        return Ok(());
    }
    let slot = backup_slot_id(group_key);
    let blob = encrypt_sync_bundle(group_key, bundle)
        .map_err(|e| P2pError::Crypto(e.to_string()))?;
    let sig = backup_write_signature(group_key, bundle.revision, &blob);

    let client = reqwest::Client::new();
    let res = client
        .put(format!("{base}/v1/backup/{slot}"))
        .header("x-curb-revision", bundle.revision.to_string())
        .header("x-curb-sig", sig)
        .body(blob)
        .send()
        .await
        .map_err(|e| P2pError::Network(format!("Backup upload failed: {e}")))?;

    if res.status().is_success() || res.status().as_u16() == 409 {
        // 409 Conflict means a newer revision is already stored; caller can pull it.
        Ok(())
    } else {
        Err(P2pError::Network(format!(
            "Relay rejected backup upload: HTTP {}",
            res.status()
        )))
    }
}

/// Downloads and decrypts the latest [`SyncBundle`] from `curb-relay` if newer than `local_rev`.
/// Returns `Ok(None)` if no backup exists yet or if the server responds `304 Not Modified`.
pub async fn download_encrypted_backup(
    relay_url: &str,
    group_key: &[u8; 32],
    local_rev: u64,
) -> Result<Option<SyncBundle>> {
    let base = relay_url.trim_end_matches('/');
    if base.is_empty() {
        return Ok(None);
    }
    let slot = backup_slot_id(group_key);
    let client = reqwest::Client::new();
    let mut req = client.get(format!("{base}/v1/backup/{slot}"));
    if local_rev > 0 {
        req = req.header("if-none-match", format!("\"{local_rev}\""));
    }
    let res = req
        .send()
        .await
        .map_err(|e| P2pError::Network(format!("Backup download failed: {e}")))?;

    if res.status().as_u16() == 304 || res.status().as_u16() == 404 {
        return Ok(None);
    }
    if !res.status().is_success() {
        return Err(P2pError::Network(format!(
            "Relay returned HTTP {} on backup download",
            res.status()
        )));
    }
    let bytes = res
        .bytes()
        .await
        .map_err(|e| P2pError::Network(format!("Failed reading backup body: {e}")))?;
    let bundle =
        decrypt_sync_bundle(group_key, &bytes).map_err(|e| P2pError::Crypto(e.to_string()))?;
    Ok(Some(bundle))
}
