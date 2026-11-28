use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::{DateTime, Utc};
use curb_core::sync::{
    decrypt_invite_descriptor, encrypt_invite_descriptor, invite_owner_token, invite_slot_id,
    InviteDescriptor, PeerPresence,
};
use serde::{Deserialize, Serialize};

use crate::{P2pError, Result};

/// An offline invite claim retrieved by the host from `GET /v1/invites/{slot_id}/claim`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteClaim {
    pub from_peer_id: String,
    pub payload: String,
    pub claimed_at: DateTime<Utc>,
}

fn http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| P2pError::Network(format!("HTTP client error: {e}")))
}

fn normalize_base(relay_url: &str) -> String {
    let trimmed = relay_url.trim().trim_end_matches('/');
    if let Some(rest) = trimmed.strip_prefix("wss://") {
        format!("https://{rest}")
    } else if let Some(rest) = trimmed.strip_prefix("ws://") {
        format!("http://{rest}")
    } else if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    }
}

/// Uploads an E2E-encrypted [`InviteDescriptor`] to the relay's zero-knowledge invite dropbox.
pub async fn publish_invite_descriptor(
    relay_url: &str,
    code: &str,
    host_peer_id: &str,
    desc: &InviteDescriptor,
    ttl_secs: u64,
) -> Result<()> {
    let slot = invite_slot_id(code);
    let owner = invite_owner_token(code, host_peer_id);
    let blob = encrypt_invite_descriptor(code, desc)
        .map_err(|e| P2pError::Crypto(e.to_string()))?;

    let url = format!("{}/v1/invites/{slot}", normalize_base(relay_url));
    let res = http_client()?
        .put(&url)
        .header("x-curb-owner-token", owner)
        .header("x-curb-ttl-secs", ttl_secs.to_string())
        .body(blob)
        .send()
        .await
        .map_err(|e| P2pError::Network(format!("Failed uploading invite: {e}")))?;

    if res.status().is_success() {
        Ok(())
    } else {
        let status = res.status();
        let text = res.text().await.unwrap_or_default();
        Err(P2pError::Network(format!(
            "Relay rejected invite upload ({status}): {text}"
        )))
    }
}

/// Fetches the raw encrypted invite descriptor bytes for `slot_id` from `curb-relay`.
pub async fn fetch_invite_descriptor_raw(relay_url: &str, slot_id: &str) -> Result<Vec<u8>> {
    let url = format!("{}/v1/invites/{slot_id}", normalize_base(relay_url));
    let res = http_client()?
        .get(&url)
        .send()
        .await
        .map_err(|e| P2pError::Network(format!("Could not reach relay: {e}")))?;

    if res.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(P2pError::Network(
            "Invite code not found or expired.".into(),
        ));
    }
    if res.status() == reqwest::StatusCode::CONFLICT {
        return Err(P2pError::Network(
            "This invite code has already been used.".into(),
        ));
    }
    if !res.status().is_success() {
        let status = res.status();
        let text = res.text().await.unwrap_or_default();
        return Err(P2pError::Network(format!(
            "Relay error fetching invite ({status}): {text}"
        )));
    }
    res.bytes()
        .await
        .map(|b| b.to_vec())
        .map_err(|e| P2pError::Network(format!("Failed reading invite body: {e}")))
}

/// Fetches the raw encrypted invite descriptor for `slot_id` and returns it as base64.
pub async fn fetch_invite_descriptor_b64(relay_url: &str, slot_id: &str) -> Result<String> {
    let raw = fetch_invite_descriptor_raw(relay_url, slot_id).await?;
    Ok(B64.encode(raw))
}

/// Decrypts a base64-encoded encrypted invite descriptor using `code`.
pub fn decrypt_invite_descriptor_b64(code: &str, blob_b64: &str) -> Result<InviteDescriptor> {
    let raw = B64
        .decode(blob_b64.trim())
        .map_err(|e| P2pError::Crypto(format!("Invalid base64 invite data: {e}")))?;
    decrypt_invite_descriptor(code, &raw).map_err(|e| P2pError::Crypto(e.to_string()))
}

/// Fetches and decrypts an [`InviteDescriptor`] using the short invite `code`.
pub async fn fetch_invite_descriptor(relay_url: &str, code: &str) -> Result<InviteDescriptor> {
    let slot = invite_slot_id(code);
    let raw = fetch_invite_descriptor_raw(relay_url, &slot).await?;
    decrypt_invite_descriptor(code, &raw).map_err(|e| P2pError::Crypto(e.to_string()))
}

/// Submits an E2E-encrypted offline invite claim to `POST /v1/invites/{slot_id}/claim`.
pub async fn submit_invite_claim(
    relay_url: &str,
    slot_id: &str,
    from_peer_id: &str,
    payload: &str,
) -> Result<()> {
    let url = format!("{}/v1/invites/{slot_id}/claim", normalize_base(relay_url));
    let res = http_client()?
        .post(&url)
        .json(&serde_json::json!({
            "from_peer_id": from_peer_id,
            "payload": payload,
        }))
        .send()
        .await
        .map_err(|e| P2pError::Network(format!("Failed submitting offline invite claim: {e}")))?;

    if res.status().is_success() {
        Ok(())
    } else if res.status() == reqwest::StatusCode::CONFLICT {
        Err(P2pError::Network(
            "This invite code has already been claimed.".into(),
        ))
    } else if res.status() == reqwest::StatusCode::NOT_FOUND {
        Err(P2pError::Network(
            "Invite code not found or expired.".into(),
        ))
    } else {
        let status = res.status();
        let text = res.text().await.unwrap_or_default();
        Err(P2pError::Network(format!(
            "Relay rejected invite claim ({status}): {text}"
        )))
    }
}

/// Polls `GET /v1/invites/{slot_id}/claim` for an offline friend claim.
/// Returns `Ok(None)` if not yet claimed (204) or expired/missing (404).
pub async fn poll_invite_claim(
    relay_url: &str,
    code: &str,
    host_peer_id: &str,
) -> Result<Option<InviteClaim>> {
    let slot = invite_slot_id(code);
    let owner = invite_owner_token(code, host_peer_id);
    let url = format!("{}/v1/invites/{slot}/claim", normalize_base(relay_url));
    let res = http_client()?
        .get(&url)
        .header("x-curb-owner-token", owner)
        .send()
        .await
        .map_err(|e| P2pError::Network(format!("Failed polling invite claim: {e}")))?;

    if res.status() == reqwest::StatusCode::NO_CONTENT
        || res.status() == reqwest::StatusCode::NOT_FOUND
    {
        return Ok(None);
    }
    if !res.status().is_success() {
        let status = res.status();
        let text = res.text().await.unwrap_or_default();
        return Err(P2pError::Network(format!(
            "Relay error polling invite claim ({status}): {text}"
        )));
    }
    let claim = res
        .json::<InviteClaim>()
        .await
        .map_err(|e| P2pError::Network(format!("Invalid invite claim JSON: {e}")))?;
    Ok(Some(claim))
}

/// Deletes an invite slot on `curb-relay` after it has been redeemed or expired.
pub async fn delete_invite_slot(
    relay_url: &str,
    code: &str,
    host_peer_id: &str,
) -> Result<()> {
    let slot = invite_slot_id(code);
    let owner = invite_owner_token(code, host_peer_id);
    let url = format!("{}/v1/invites/{slot}", normalize_base(relay_url));
    let _ = http_client()?
        .delete(&url)
        .header("x-curb-owner-token", owner)
        .send()
        .await;
    Ok(())
}

#[derive(Deserialize)]
struct BatchPresenceResponse {
    peers: Vec<PeerPresence>,
}

/// Queries online/last-seen presence for a batch of peer IDs via `POST /v1/presence`.
pub async fn fetch_peers_presence(
    relay_url: &str,
    peer_ids: &[String],
) -> Result<Vec<PeerPresence>> {
    if peer_ids.is_empty() {
        return Ok(Vec::new());
    }
    let url = format!("{}/v1/presence", normalize_base(relay_url));
    let res = http_client()?
        .post(&url)
        .json(&serde_json::json!({ "peer_ids": peer_ids }))
        .send()
        .await
        .map_err(|e| P2pError::Network(format!("Failed querying presence: {e}")))?;

    if !res.status().is_success() {
        let status = res.status();
        let text = res.text().await.unwrap_or_default();
        return Err(P2pError::Network(format!(
            "Relay presence error ({status}): {text}"
        )));
    }
    let body = res
        .json::<BatchPresenceResponse>()
        .await
        .map_err(|e| P2pError::Network(format!("Invalid presence JSON: {e}")))?;
    Ok(body.peers)
}
