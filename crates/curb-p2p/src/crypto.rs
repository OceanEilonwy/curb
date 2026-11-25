use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;

use crate::identity::PeerIdentity;
use crate::{P2pError, Result};

fn derive_session_key(my_id: &PeerIdentity, their_peer_id: &str) -> Result<[u8; 32]> {
    let shared = my_id.diffie_hellman(their_peer_id)?;
    let derived = blake3::keyed_hash(&shared, b"curb-p2p-e2e-xchacha20poly1305-v1");
    Ok(*derived.as_bytes())
}

/// Encrypts `plaintext` end-to-end for `their_peer_id`, returning a base64 string
/// containing `[24-byte nonce || ciphertext + 16-byte Poly1305 tag]`.
pub fn encrypt_for_peer(
    my_id: &PeerIdentity,
    their_peer_id: &str,
    plaintext: &[u8],
) -> Result<String> {
    let key = derive_session_key(my_id, their_peer_id)?;
    let cipher = XChaCha20Poly1305::new((&key).into());
    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| P2pError::Crypto("E2E encryption failed".into()))?;
    let mut combined = Vec::with_capacity(24 + ct.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ct);
    Ok(B64.encode(combined))
}

/// Decrypts a base64 ciphertext sent by `their_peer_id`.
pub fn decrypt_from_peer(
    my_id: &PeerIdentity,
    their_peer_id: &str,
    payload_b64: &str,
) -> Result<Vec<u8>> {
    let raw = B64
        .decode(payload_b64.trim())
        .map_err(|e| P2pError::Crypto(format!("Invalid base64 payload: {e}")))?;
    if raw.len() < 24 + 16 {
        return Err(P2pError::Crypto("Encrypted payload too short".into()));
    }
    let (nonce_bytes, ct) = raw.split_at(24);
    let key = derive_session_key(my_id, their_peer_id)?;
    let cipher = XChaCha20Poly1305::new((&key).into());
    let nonce = XNonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ct)
        .map_err(|_| P2pError::Crypto("E2E decryption/authentication failed".into()))
}
