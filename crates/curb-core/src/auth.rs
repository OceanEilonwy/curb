use std::collections::HashMap;
use std::time::{Duration, Instant};

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::{CurbError, Result};

/// Stored in `C:\ProgramData\Curb\auth.json` (writable only by SYSTEM / Administrators).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRecord {
    pub password_hash: String,
    pub updated_at: DateTime<Utc>,
}

/// Hashes a plain-text Curb admin password using Argon2id with a fresh random salt.
pub fn hash_password(password: &str) -> Result<AuthRecord> {
    if password.len() < 4 {
        return Err(CurbError::Auth(
            "Password must be at least 4 characters long.".into(),
        ));
    }
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| CurbError::Auth(format!("Failed to hash password: {e}")))?
        .to_string();

    Ok(AuthRecord {
        password_hash: hash,
        updated_at: Utc::now(),
    })
}

/// Verifies a plain-text password against a stored `AuthRecord`.
pub fn verify_password(password: &str, record: &AuthRecord) -> bool {
    let Ok(parsed) = PasswordHash::new(&record.password_hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
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

    /// Attempts to unlock with `password` against `record`, returning a random session token.
    pub fn unlock(&mut self, password: &str, record: &AuthRecord) -> Result<String> {
        let now = Instant::now();
        if let Some(until) = self.locked_until {
            if now < until {
                let secs = (until - now).as_secs().max(1);
                return Err(CurbError::Auth(format!(
                    "Too many failed attempts. Try again in {secs}s."
                )));
            }
        }

        if !verify_password(password, record) {
            self.failed_attempts = self.failed_attempts.saturating_add(1);
            if self.failed_attempts >= 3 {
                let shift = (self.failed_attempts - 3).min(6);
                let backoff = Duration::from_secs(2u64 << shift);
                self.locked_until = Some(now + backoff);
            }
            return Err(CurbError::Auth("Incorrect Curb password.".into()));
        }

        self.failed_attempts = 0;
        self.locked_until = None;
        self.prune_expired();

        let token = generate_token();
        self.sessions.insert(
            token.clone(),
            ActiveSession {
                expires_at: now + self.idle_timeout,
                idle_timeout: self.idle_timeout,
            },
        );
        Ok(token)
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

    /// Revokes all active sessions (e.g. after a password change).
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
