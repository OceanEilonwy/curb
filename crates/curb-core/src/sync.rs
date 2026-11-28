use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;

use crate::auth::AdminCredential;
use crate::config::Config;
use crate::{CurbError, Result};

type HmacSha256 = Hmac<Sha256>;

/// Default public relay URL (can be overridden by self-hosted relay URLs).
pub const DEFAULT_RELAY_URL: &str = "https://relay.curb.app";

/// Kind of single-use invite encoded in a `curb://invite?...` link / QR code.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InviteKind {
    /// Invites a remote friend to connect from their Curb app and set their own admin password.
    FriendAdmin,
    /// Invites another device owned by the user to join the P2P sync group.
    SyncDevice,
}

/// Single-use invite payload encoded as a `curb://invite?...` URI (and QR code).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InviteToken {
    pub kind: InviteKind,
    /// Ed25519 public key (hex) of the host `curb-service`.
    pub target_peer_id: String,
    /// Relay proxy URL used for P2P discovery & fallback tunneling.
    pub relay_url: String,
    /// Short-lived, single-use random secret redeemed once during pairing.
    pub code: String,
    /// Friendly name of the host device (e.g. "Jordan's PC").
    pub device_name: String,
    /// Optional direct LAN/public `ip:port` hint for instant direct P2P without relay round-trip.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direct_addr: Option<String>,
}

impl InviteToken {
    /// Serializes this invite into a compact `curb://invite?...` URI.
    pub fn to_uri(&self) -> String {
        let kind = match self.kind {
            InviteKind::FriendAdmin => "friend",
            InviteKind::SyncDevice => "device",
        };
        let mut uri = format!(
            "curb://invite?kind={}&peer={}&relay={}&code={}&name={}",
            kind,
            pct_encode(&self.target_peer_id),
            pct_encode(&self.relay_url),
            pct_encode(&self.code),
            pct_encode(&self.device_name),
        );
        if let Some(addr) = &self.direct_addr {
            if !addr.is_empty() {
                uri.push_str("&addr=");
                uri.push_str(&pct_encode(addr));
            }
        }
        uri
    }

    /// Serializes this invite into a short `curb://join?...` URI (or bare code when using the default relay)
    /// that resolves via the relay's zero-knowledge invite dropbox.
    pub fn to_short_uri(&self) -> String {
        let relay = self.relay_url.trim().trim_end_matches('/');
        if relay.is_empty() || relay.eq_ignore_ascii_case(DEFAULT_RELAY_URL) {
            self.code.clone()
        } else {
            format!(
                "curb://join?code={}&relay={}",
                pct_encode(&self.code),
                pct_encode(relay),
            )
        }
    }

    /// Parses a `curb://invite?...` URI back into an [`InviteToken`].
    pub fn parse_uri(uri: &str) -> Result<Self> {
        let trimmed = uri.trim();
        let query = trimmed
            .strip_prefix("curb://invite?")
            .ok_or_else(|| CurbError::Config("Invite link must start with 'curb://invite?'".into()))?;

        let mut kind = InviteKind::FriendAdmin;
        let mut target_peer_id = None;
        let mut relay_url = None;
        let mut code = None;
        let mut device_name = None;
        let mut direct_addr = None;

        for pair in query.split('&') {
            let Some((k, v)) = pair.split_once('=') else {
                continue;
            };
            let decoded = pct_decode(v)?;
            match k {
                "kind" => {
                    kind = match decoded.as_str() {
                        "friend" | "friend_admin" => InviteKind::FriendAdmin,
                        "device" | "sync_device" => InviteKind::SyncDevice,
                        other => {
                            return Err(CurbError::Config(format!(
                                "Unknown invite kind '{other}'"
                            )));
                        }
                    };
                }
                "peer" => target_peer_id = Some(decoded),
                "relay" => relay_url = Some(decoded),
                "code" => code = Some(decoded),
                "name" => device_name = Some(decoded),
                "addr" => {
                    if !decoded.is_empty() {
                        direct_addr = Some(decoded);
                    }
                }
                _ => {}
            }
        }

        let target_peer_id = target_peer_id
            .filter(|s| !s.is_empty())
            .ok_or_else(|| CurbError::Config("Invite link is missing 'peer'".into()))?;
        let relay_url = relay_url
            .filter(|s| !s.is_empty())
            .ok_or_else(|| CurbError::Config("Invite link is missing 'relay'".into()))?;
        let code = code
            .filter(|s| !s.is_empty())
            .ok_or_else(|| CurbError::Config("Invite link is missing 'code'".into()))?;
        let device_name = device_name
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "Friend's PC".into());

        Ok(Self {
            kind,
            target_peer_id,
            relay_url,
            code,
            device_name,
            direct_addr,
        })
    }
}

/// Parsed user input when connecting to a friend: either a full legacy `curb://invite?...` URI
/// or a short invite code / `curb://join?code=...` link resolved via the relay dropbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedInviteInput {
    Full(InviteToken),
    Short { code: String, relay_url: String },
}

impl ParsedInviteInput {
    /// Parses a full `curb://invite?...` URI, a short `curb://join?code=...` URI,
    /// or a bare human-friendly invite code (e.g. `K7M4-QP9X-2N8V-R5JT`).
    pub fn parse(input: &str) -> Result<Self> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(CurbError::Config(
                "Please enter an invite code or link.".into(),
            ));
        }
        if trimmed.starts_with("curb://invite?") {
            return Ok(Self::Full(InviteToken::parse_uri(trimmed)?));
        }
        if let Some(query) = trimmed.strip_prefix("curb://join?") {
            let mut code = None;
            let mut relay_url = None;
            for pair in query.split('&') {
                let Some((k, v)) = pair.split_once('=') else {
                    continue;
                };
                let decoded = pct_decode(v)?;
                match k {
                    "code" => code = Some(decoded),
                    "relay" => relay_url = Some(decoded),
                    _ => {}
                }
            }
            let raw_code = code
                .filter(|s| !s.trim().is_empty())
                .ok_or_else(|| CurbError::Config("Invite link is missing 'code'".into()))?;
            let normalized = normalize_invite_code(&raw_code);
            if normalized.len() < 8 {
                return Err(CurbError::Config("Invite code is too short.".into()));
            }
            let relay = relay_url
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| DEFAULT_RELAY_URL.to_string());
            return Ok(Self::Short {
                code: normalized,
                relay_url: relay,
            });
        }
        // Bare invite code (e.g. `K7M4-QP9X-2N8V-R5JT`)
        let normalized = normalize_invite_code(trimmed);
        let valid_chars = normalized
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-');
        if valid_chars && (8..=32).contains(&normalized.len()) && !trimmed.contains("://") {
            return Ok(Self::Short {
                code: normalized,
                relay_url: DEFAULT_RELAY_URL.to_string(),
            });
        }
        Err(CurbError::Config(
            "Enter a valid invite code (e.g. K7M4-QP9X-2N8V-R5JT) or curb:// invite link.".into(),
        ))
    }
}

/// Normalizes an invite code by trimming, removing whitespace, and uppercasing.
pub fn normalize_invite_code(code: &str) -> String {
    code.chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_uppercase()
}

/// Encrypted invite descriptor stored in `curb-relay`'s zero-knowledge invite dropbox.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InviteDescriptor {
    pub kind: InviteKind,
    pub target_peer_id: String,
    pub device_name: String,
    pub expires_at: DateTime<Utc>,
}

/// Persisted pending invite stored by `curb-service` so invites survive restarts and sleep.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingInviteRecord {
    pub code: String,
    pub kind: InviteKind,
    pub expires_at: DateTime<Utc>,
    #[serde(default)]
    pub published: bool,
}

/// Presence information for a remote peer reported by `curb-relay`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerPresence {
    pub peer_id: String,
    pub online: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<DateTime<Utc>>,
}

/// Derives the opaque 64-char hex lookup ID for an invite dropbox slot on `curb-relay`.
pub fn invite_slot_id(code: &str) -> String {
    let norm = normalize_invite_code(code);
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"curb-invite-slot-v1:");
    hasher.update(norm.as_bytes());
    hasher.finalize().to_hex().to_string()
}

/// Derives an owner-only write/poll/delete token authenticating the host for `/v1/invites/{slot_id}`.
pub fn invite_owner_token(code: &str, host_peer_id: &str) -> String {
    let norm = normalize_invite_code(code);
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"curb-invite-owner-v1:");
    hasher.update(norm.as_bytes());
    hasher.update(b":");
    hasher.update(host_peer_id.trim().as_bytes());
    hasher.finalize().to_hex().to_string()
}

fn invite_aead_key(code: &str) -> [u8; 32] {
    let norm = normalize_invite_code(code);
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"curb-invite-aead-v1:");
    hasher.update(norm.as_bytes());
    *hasher.finalize().as_bytes()
}

/// Encrypts an [`InviteDescriptor`] using XChaCha20-Poly1305 keyed from the invite code.
pub fn encrypt_invite_descriptor(code: &str, desc: &InviteDescriptor) -> Result<Vec<u8>> {
    let key = invite_aead_key(code);
    let cipher = XChaCha20Poly1305::new((&key).into());
    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let plaintext = serde_json::to_vec(desc)?;
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|_| CurbError::Config("Failed to encrypt invite descriptor".into()))?;

    let mut out = Vec::with_capacity(24 + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypts an [`InviteDescriptor`] fetched from `curb-relay` using the invite code.
pub fn decrypt_invite_descriptor(code: &str, blob: &[u8]) -> Result<InviteDescriptor> {
    if blob.len() < 24 + 16 {
        return Err(CurbError::Config(
            "Encrypted invite descriptor is truncated".into(),
        ));
    }
    let (nonce_bytes, ciphertext) = blob.split_at(24);
    let key = invite_aead_key(code);
    let cipher = XChaCha20Poly1305::new((&key).into());
    let nonce = XNonce::from_slice(nonce_bytes);

    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| {
        CurbError::Auth("Invalid invite code or corrupted invite data.".into())
    })?;
    Ok(serde_json::from_slice(&plaintext)?)
}

/// Public summary of a configured admin (never exposes password hashes).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemoteAdminSummary {
    pub id: Uuid,
    pub name: String,
    pub is_remote: bool,
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub last_unlock_at: Option<DateTime<Utc>>,
}

/// Summary of a device belonging to the same P2P sync group.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncedDeviceInfo {
    pub peer_id: String,
    pub name: String,
    pub os: String,
    pub online: bool,
    pub last_seen_at: DateTime<Utc>,
    pub applied_revision: u64,
}

/// Persisted P2P sync & remote admin configuration stored by `curb-service`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemoteSyncConfig {
    /// Friendly name of this device (e.g. "Jordan's PC"), editable by the user/admin.
    pub device_name: String,
    /// Optional relay proxy URL (empty string disables remote/relay networking).
    #[serde(default)]
    pub relay_url: String,
    /// When true, `curb-service` uploads an E2E-encrypted settings backup to the relay
    /// whenever config changes so sleeping devices catch up on wake.
    #[serde(default = "default_true")]
    pub encrypted_backup_enabled: bool,
    /// 32-byte hex-encoded symmetric key shared across devices in the same sync group.
    pub group_key_hex: String,
    /// Monotonically increasing config revision number for P2P & backup sync.
    #[serde(default = "default_one")]
    pub revision: u64,
    /// Known peer devices in this user's sync group.
    #[serde(default)]
    pub synced_devices: Vec<SyncedDeviceInfo>,
}

fn default_true() -> bool {
    true
}

fn default_one() -> u64 {
    1
}

impl RemoteSyncConfig {
    /// Creates a fresh local sync config with a random 256-bit group key.
    pub fn new_default(device_name: impl Into<String>) -> Self {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        Self {
            device_name: device_name.into(),
            relay_url: String::new(),
            encrypted_backup_enabled: true,
            group_key_hex: hex::encode(key),
            revision: 1,
            synced_devices: Vec::new(),
        }
    }

    pub fn group_key_bytes(&self) -> Result<[u8; 32]> {
        let decoded = hex::decode(&self.group_key_hex)
            .map_err(|e| CurbError::Config(format!("Invalid group key hex: {e}")))?;
        decoded
            .try_into()
            .map_err(|_| CurbError::Config("Group key must be 32 bytes".into()))
    }
}

/// Live WebSocket connection state between `curb-service` and `curb-relay`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RelayConnectionState {
    /// No relay URL is configured (remote sync disabled).
    #[default]
    Disabled,
    /// Attempting to establish (or re-establish) the WebSocket connection.
    Connecting,
    /// Actively connected to the configured `curb-relay`.
    Connected,
    /// Last connection attempt failed (retrying in the background).
    Disconnected,
}

/// Read-only status returned to `curb-app` for rendering the device name, admins, and Settings -> Advanced.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RemoteStatus {
    pub device_name: String,
    pub peer_id: String,
    pub relay_url: String,
    pub relay_connected: bool,
    #[serde(default)]
    pub relay_state: RelayConnectionState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_error: Option<String>,
    pub encrypted_backup_enabled: bool,
    pub revision: u64,
    pub admins: Vec<RemoteAdminSummary>,
    pub synced_devices: Vec<SyncedDeviceInfo>,
}

/// Payload synchronized directly P2P between devices (and optionally stored E2E-encrypted on `curb-relay`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncBundle {
    pub revision: u64,
    pub updated_at: DateTime<Utc>,
    pub origin_device_name: String,
    pub config: Config,
    #[serde(default)]
    pub admins: Vec<AdminCredential>,
}

/// Derives the opaque, zero-knowledge backup slot ID from `group_key`.
/// The relay server only ever sees this hash—never the key or vault metadata.
pub fn backup_slot_id(group_key: &[u8; 32]) -> String {
    let mut hasher = blake3::Hasher::new_keyed(group_key);
    hasher.update(b"curb-backup-slot-v1");
    hasher.finalize().to_hex().to_string()
}

/// Computes an HMAC-SHA256 write proof authenticating `PUT /v1/backup/{slot_id}`.
pub fn backup_write_signature(group_key: &[u8; 32], revision: u64, ciphertext: &[u8]) -> String {
    let write_key = blake3::keyed_hash(group_key, b"curb-backup-write-key-v1");
    let mut mac = <HmacSha256 as Mac>::new_from_slice(write_key.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(&revision.to_be_bytes());
    mac.update(ciphertext);
    hex::encode(mac.finalize().into_bytes())
}

/// Encrypts a [`SyncBundle`] using XChaCha20-Poly1305 with a fresh 24-byte random nonce.
/// Output format: `[24-byte nonce || ciphertext + 16-byte tag]`.
pub fn encrypt_sync_bundle(group_key: &[u8; 32], bundle: &SyncBundle) -> Result<Vec<u8>> {
    let enc_key = blake3::keyed_hash(group_key, b"curb-backup-aead-key-v1");
    let cipher = XChaCha20Poly1305::new(enc_key.as_bytes().into());
    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let plaintext = serde_json::to_vec(bundle)?;
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|_| CurbError::Config("Failed to encrypt sync bundle".into()))?;

    let mut out = Vec::with_capacity(24 + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypts an encrypted sync bundle produced by [`encrypt_sync_bundle`].
pub fn decrypt_sync_bundle(group_key: &[u8; 32], blob: &[u8]) -> Result<SyncBundle> {
    if blob.len() < 24 + 16 {
        return Err(CurbError::Config("Encrypted sync bundle is truncated".into()));
    }
    let (nonce_bytes, ciphertext) = blob.split_at(24);
    let enc_key = blake3::keyed_hash(group_key, b"curb-backup-aead-key-v1");
    let cipher = XChaCha20Poly1305::new(enc_key.as_bytes().into());
    let nonce = XNonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CurbError::Auth("Failed to decrypt sync bundle (wrong group key or tampered data)".into()))?;
    let bundle = serde_json::from_slice::<SyncBundle>(&plaintext)?;
    Ok(bundle)
}

/// Generates a human-friendly, high-entropy single-use invite code (e.g. `K7M4-QP9X-2N8V-R5JT`).
pub fn generate_invite_code() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    let chars: Vec<char> = bytes
        .iter()
        .map(|b| ALPHABET[(*b as usize) % ALPHABET.len()] as char)
        .collect();
    format!(
        "{}-{}-{}-{}",
        chars[0..4].iter().collect::<String>(),
        chars[4..8].iter().collect::<String>(),
        chars[8..12].iter().collect::<String>(),
        chars[12..16].iter().collect::<String>(),
    )
}

fn pct_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn pct_decode(input: &str) -> Result<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex_str = std::str::from_utf8(&bytes[i + 1..i + 3])
                .map_err(|_| CurbError::Config("Invalid percent encoding in invite link".into()))?;
            let val = u8::from_str_radix(hex_str, 16)
                .map_err(|_| CurbError::Config("Invalid hex escape in invite link".into()))?;
            out.push(val);
            i += 3;
        } else if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out)
        .map_err(|_| CurbError::Config("Invalid UTF-8 in invite link".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invite_uri_round_trip_preserves_spaces_and_special_chars() {
        let invite = InviteToken {
            kind: InviteKind::FriendAdmin,
            target_peer_id: "7f3a91c2deadbeef".into(),
            relay_url: "https://relay.curb.app:8443".into(),
            code: "K7M4-QP9X-2N8V-R5JT".into(),
            device_name: "Jordan's Gaming PC".into(),
            direct_addr: Some("192.168.1.42:49200".into()),
        };

        let uri = invite.to_uri();
        assert!(uri.starts_with("curb://invite?"));
        let parsed = InviteToken::parse_uri(&uri).expect("parse uri");
        assert_eq!(parsed, invite);
    }

    #[test]
    fn sync_bundle_encrypt_decrypt_round_trip_and_tamper_detection() {
        let cfg = RemoteSyncConfig::new_default("Jordan's PC");
        let key = cfg.group_key_bytes().expect("key");
        let bundle = SyncBundle {
            revision: 7,
            updated_at: Utc::now(),
            origin_device_name: "Jordan's PC".into(),
            config: Config::default(),
            admins: Vec::new(),
        };

        let encrypted = encrypt_sync_bundle(&key, &bundle).expect("encrypt");
        let decrypted = decrypt_sync_bundle(&key, &encrypted).expect("decrypt");
        assert_eq!(decrypted.revision, 7);
        assert_eq!(decrypted.origin_device_name, "Jordan's PC");

        // Wrong key fails authentication
        let mut wrong_key = key;
        wrong_key[0] ^= 0xff;
        assert!(decrypt_sync_bundle(&wrong_key, &encrypted).is_err());

        // Tampered ciphertext fails authentication
        let mut tampered = encrypted.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(decrypt_sync_bundle(&key, &tampered).is_err());

        // Slot ID and write signature are deterministic
        let slot = backup_slot_id(&key);
        assert_eq!(slot.len(), 64);
        let sig1 = backup_write_signature(&key, 7, &encrypted);
        let sig2 = backup_write_signature(&key, 7, &encrypted);
        assert_eq!(sig1, sig2);
    }
}
