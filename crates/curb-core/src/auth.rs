use std::collections::HashMap;
use std::time::{Duration, Instant};

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use uuid::Uuid;

use crate::sync::RemoteAdminSummary;
use crate::{CurbError, Result};

/// A named admin credential (e.g. a remote friend who connected via a one-time
/// invite link and chose their own Argon2id password).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdminCredential {
    pub id: Uuid,
    pub name: String,
    /// Ed25519 peer ID (hex) of the remote friend's `curb-app` device.
    #[serde(default)]
    pub peer_id: Option<String>,
    pub password_hash: String,
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub last_unlock_at: Option<DateTime<Utc>>,
}

impl AdminCredential {
    pub fn to_summary(&self) -> RemoteAdminSummary {
        RemoteAdminSummary {
            id: self.id,
            name: self.name.clone(),
            is_remote: self.peer_id.is_some(),
            created_at: self.created_at,
            last_unlock_at: self.last_unlock_at,
        }
    }
}

/// Stored in `C:\ProgramData\Curb\auth.json` (writable only by SYSTEM / Administrators).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRecord {
    pub password_hash: String,
    pub updated_at: DateTime<Utc>,
    /// Additional named admins (e.g. remote friends), each with their own Argon2id password.
    #[serde(default)]
    pub admins: Vec<AdminCredential>,
}

/// Hashes a raw password string using Argon2id with a fresh random salt.
pub fn hash_password_raw(password: &str) -> Result<String> {
    if password.len() < 4 {
        return Err(CurbError::Auth(
            "Password must be at least 4 characters long.".into(),
        ));
    }
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| CurbError::Auth(format!("Failed to hash password: {e}")))
        .map(|h| h.to_string())
}

/// Verifies a plain-text password against an Argon2id hash string.
pub fn verify_hash(password: &str, hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// Hashes a plain-text Curb admin password using Argon2id with a fresh random salt.
pub fn hash_password(password: &str) -> Result<AuthRecord> {
    let hash = hash_password_raw(password)?;
    Ok(AuthRecord {
        password_hash: hash,
        updated_at: Utc::now(),
        admins: Vec::new(),
    })
}

/// Verifies a plain-text password against a stored `AuthRecord` (primary password).
pub fn verify_password(password: &str, record: &AuthRecord) -> bool {
    verify_hash(password, &record.password_hash)
}

impl AuthRecord {
    /// Adds a new named admin (e.g. a remote friend who redeemed a one-time invite)
    /// with their own Argon2id password.
    pub fn add_admin(
        &mut self,
        name: impl Into<String>,
        peer_id: Option<String>,
        password: &str,
    ) -> Result<AdminCredential> {
        let name = name.into().trim().to_string();
        if name.is_empty() {
            return Err(CurbError::Auth("Admin name cannot be empty.".into()));
        }
        let password_hash = hash_password_raw(password)?;
        // Replace any previous entry for the same peer_id so re-pairing stays clean.
        if let Some(pid) = &peer_id {
            self.admins
                .retain(|a| a.peer_id.as_deref() != Some(pid.as_str()));
        }
        let cred = AdminCredential {
            id: Uuid::new_v4(),
            name,
            peer_id,
            password_hash,
            created_at: Utc::now(),
            last_unlock_at: None,
        };
        self.admins.push(cred.clone());
        self.updated_at = Utc::now();
        Ok(cred)
    }

    /// Removes a named admin by ID. Returns `true` if an entry was removed.
    pub fn remove_admin(&mut self, admin_id: Uuid) -> bool {
        let before = self.admins.len();
        self.admins.retain(|a| a.id != admin_id);
        let removed = self.admins.len() != before;
        if removed {
            self.updated_at = Utc::now();
        }
        removed
    }

    /// Verifies a remote friend's `peer_id` + personal password, returning the matching admin's ID.
    pub fn verify_peer(&self, peer_id: &str, password: &str) -> Option<Uuid> {
        self.admins
            .iter()
            .find(|a| a.peer_id.as_deref() == Some(peer_id) && verify_hash(password, &a.password_hash))
            .map(|a| a.id)
    }

    /// Lists all configured remote/named admins (without password hashes).
    pub fn admin_summaries(&self) -> Vec<RemoteAdminSummary> {
        self.admins.iter().map(AdminCredential::to_summary).collect()
    }
}

#[derive(Debug, Clone)]
struct ActiveSession {
    expires_at: Instant,
    idle_timeout: Duration,
}

/// In-memory session manager held by `curb-service`.
/// Issues short-lived random 256-bit tokens upon valid password unlock and
/// applies exponential backoff on repeated failed guesses.
#[derive(Debug)]
pub struct SessionManager {
    sessions: HashMap<String, ActiveSession>,
    idle_timeout: Duration,
    failed_attempts: u32,
    locked_until: Option<Instant>,
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new(Duration::from_secs(600))
    }
}

impl SessionManager {
    pub fn new(idle_timeout: Duration) -> Self {
        Self {
            sessions: HashMap::new(),
            idle_timeout,
            failed_attempts: 0,
            locked_until: None,
        }
    }

    /// Returns an error while the failed-attempt back-off window is active.
    ///
    /// Together with [`Self::finish_unlock`] this lets callers run the (slow) Argon2
    /// verification *outside* any shared lock.
    pub fn check_throttle(&self) -> Result<()> {
        if let Some(until) = self.locked_until {
            let now = Instant::now();
            if now < until {
                let secs = (until - now).as_secs().max(1);
                return Err(CurbError::Auth(format!(
                    "Too many failed attempts. Try again in {secs}s."
                )));
            }
        }
        Ok(())
    }

    /// Records the outcome of a password verification performed by the caller.
    /// On success issues a session token; on failure applies exponential back-off.
    pub fn finish_unlock(&mut self, verified: bool) -> Result<String> {
        self.check_throttle()?;
        if !verified {
            self.failed_attempts = self.failed_attempts.saturating_add(1);
            if self.failed_attempts >= 3 {
                let shift = (self.failed_attempts - 3).min(6);
                let backoff = Duration::from_secs(2u64 << shift);
                self.locked_until = Some(Instant::now() + backoff);
            }
            return Err(CurbError::Auth("Incorrect Curb password.".into()));
        }
        self.failed_attempts = 0;
        self.locked_until = None;
        Ok(self.issue_token())
    }

    /// Issues a fresh session token without verifying anything (first-run setup).
    pub fn issue_token(&mut self) -> String {
        self.prune_expired();
        let token = generate_token();
        self.sessions.insert(
            token.clone(),
            ActiveSession {
                expires_at: Instant::now() + self.idle_timeout,
                idle_timeout: self.idle_timeout,
            },
        );
        token
    }

    /// Attempts to unlock with `password` against `record`, returning a random session token.
    pub fn unlock(&mut self, password: &str, record: &AuthRecord) -> Result<String> {
        self.check_throttle()?;
        let ok = verify_password(password, record);
        self.finish_unlock(ok)
    }

    /// Attempts to unlock as a paired remote friend identified by `peer_id` using their
    /// personal Argon2id password, returning `(session_token, admin_id)`.
    pub fn unlock_as_peer(
        &mut self,
        peer_id: &str,
        password: &str,
        record: &AuthRecord,
    ) -> Result<(String, Uuid)> {
        self.check_throttle()?;
        let admin = record.verify_peer(peer_id, password);
        self.finish_unlock_peer(admin)
    }

    /// Records the outcome of a peer verification performed by the caller.
    pub fn finish_unlock_peer(&mut self, admin: Option<Uuid>) -> Result<(String, Uuid)> {
        match admin {
            Some(id) => {
                let token = self.finish_unlock(true)?;
                Ok((token, id))
            }
            None => self.finish_unlock(false).map(|t| (t, Uuid::nil())),
        }
    }

    /// Validates `token` and refreshes its sliding idle expiration window.
    pub fn validate_and_refresh(&mut self, token: &str) -> bool {
        let now = Instant::now();
        if let Some(session) = self.sessions.get_mut(token) {
            if session.expires_at > now {
                session.expires_at = now + session.idle_timeout;
                return true;
            }
        }
        self.sessions.remove(token);
        false
    }

    /// Revokes a single session token (called on explicit Lock or tray window close).
    pub fn lock(&mut self, token: &str) {
        self.sessions.remove(token);
    }

    /// Revokes all active sessions except `keep_token` (used when rotating the password).
    pub fn lock_all_except(&mut self, keep_token: &str) {
        self.sessions.retain(|k, _| k == keep_token);
    }

    /// Revokes all active sessions (e.g. after an administrative password reset).
    pub fn lock_all(&mut self) {
        self.sessions.clear();
    }

    pub fn prune_expired(&mut self) {
        let now = Instant::now();
        self.sessions.retain(|_, s| s.expires_at > now);
    }
}

fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hash_and_session_lifecycle() {
        let record = hash_password("my-friend-secret").expect("hash");
        assert!(verify_password("my-friend-secret", &record));
        assert!(!verify_password("wrong-password", &record));

        let mut mgr = SessionManager::new(Duration::from_secs(60));
        assert!(mgr.unlock("wrong", &record).is_err());

        let token = mgr.unlock("my-friend-secret", &record).expect("unlock");
        assert_eq!(token.len(), 64);
        assert!(mgr.validate_and_refresh(&token));

        mgr.lock(&token);
        assert!(!mgr.validate_and_refresh(&token));
    }

    #[test]
    fn backoff_engages_after_three_failures() {
        let record = hash_password("correct-horse").expect("hash");
        let mut mgr = SessionManager::default();
        for _ in 0..3 {
            assert!(mgr.unlock("bad", &record).is_err());
        }
        let err = mgr.unlock("correct-horse", &record).unwrap_err();
        assert!(err.to_string().contains("Too many failed attempts"));
    }
}
