use std::path::Path;

use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{P2pError, Result};

/// Persistent cryptographic peer identity (X25519 static keypair).
///
/// The 64-character hex public key serves as the peer's globally unique `peer_id`
/// and enables mutually authenticated, end-to-end encrypted messaging with any
/// other Curb peer without a central CA or account system.
#[derive(Clone)]
pub struct PeerIdentity {
    secret: StaticSecret,
    public: PublicKey,
}

#[derive(Serialize, Deserialize)]
struct StoredIdentity {
    secret_hex: String,
}

impl PeerIdentity {
    /// Generates a fresh random keypair.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Loads an existing identity from `path`, or generates and persists a new one.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        if path.exists() {
            let raw = std::fs::read_to_string(path)?;
            let stored: StoredIdentity = serde_json::from_str(&raw)?;
            let bytes = hex::decode(stored.secret_hex.trim())
                .map_err(|e| P2pError::Crypto(format!("Invalid identity hex: {e}")))?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| P2pError::Crypto("Identity secret must be 32 bytes".into()))?;
            let secret = StaticSecret::from(arr);
            let public = PublicKey::from(&secret);
            return Ok(Self { secret, public });
        }

        let id = Self::generate();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let stored = StoredIdentity {
            secret_hex: hex::encode(id.secret.to_bytes()),
        };
        let json = serde_json::to_string_pretty(&stored)?;
        std::fs::write(path, json)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(id)
    }

    /// Hex-encoded 32-byte public key used as this peer's `peer_id`.
    pub fn peer_id(&self) -> String {
        hex::encode(self.public.as_bytes())
    }

    pub(crate) fn diffie_hellman(&self, their_peer_id: &str) -> Result<[u8; 32]> {
        let bytes = hex::decode(their_peer_id.trim())
            .map_err(|e| P2pError::Crypto(format!("Invalid peer_id hex: {e}")))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| P2pError::Crypto("Peer ID must be 32 bytes (64 hex chars)".into()))?;
        let their_pub = PublicKey::from(arr);
        Ok(self.secret.diffie_hellman(&their_pub).to_bytes())
    }
}
