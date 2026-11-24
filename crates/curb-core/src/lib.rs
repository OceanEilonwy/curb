pub mod adaptors;
pub mod auth;
pub mod cleanup;
pub mod config;
pub mod dns;
pub mod ipc;
pub mod presets;
pub mod steam;
pub mod store;
pub mod verify;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CurbError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Authentication error: {0}")]
    Auth(String),

    #[error("Invalid configuration: {0}")]
    Config(String),

    #[error("Verification error: {0}")]
    Verify(String),

    #[error("Steam library error: {0}")]
    Steam(String),
}

pub type Result<T> = std::result::Result<T, CurbError>;
