use std::fs;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::auth::AuthRecord;
use crate::config::Config;
use crate::Result;

/// Returns the default Curb data directory:
/// - Windows: `C:\ProgramData\Curb`
/// - Non-Windows (dev): `$HOME/.local/share/curb`
pub fn default_data_dir() -> PathBuf {
    #[cfg(windows)]
    {
        if let Ok(program_data) = std::env::var("ProgramData") {
            return PathBuf::from(program_data).join("Curb");
        }
        PathBuf::from(r"C:\ProgramData\Curb")
    }

    #[cfg(not(windows))]
    {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(".local/share/curb");
        }
        PathBuf::from("/tmp/curb-data")
    }
}

pub fn config_path(data_dir: &Path) -> PathBuf {
    data_dir.join("config.json")
}

pub fn auth_path(data_dir: &Path) -> PathBuf {
    data_dir.join("auth.json")
}

pub fn dns_backup_path(data_dir: &Path) -> PathBuf {
    data_dir.join("dns_backup.json")
}

pub fn load_config(data_dir: &Path) -> Result<Config> {
    let path = config_path(data_dir);
    if !path.exists() {
        return Ok(Config::default());
    }
    let mut cfg: Config = read_json(&path)?;
    if cfg.migrate_legacy_rules() {
        let _ = save_config(data_dir, &cfg);
    }
    Ok(cfg)
}

pub fn save_config(data_dir: &Path, config: &Config) -> Result<()> {
    write_json_atomic(&config_path(data_dir), config)
}

pub fn load_auth(data_dir: &Path) -> Result<Option<AuthRecord>> {
    let path = auth_path(data_dir);
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(read_json(&path)?))
}

pub fn save_auth(data_dir: &Path, record: &AuthRecord) -> Result<()> {
    write_json_atomic(&auth_path(data_dir), record)
}

pub fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Writes JSON via a unique temporary sibling file and atomic rename (with brief
/// retries for transient Windows file locks / AV scanners) so concurrent writers
/// or crashes never corrupt config files on disk.
pub fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension(format!("json.{}.tmp", uuid::Uuid::new_v4()));
    let json = serde_json::to_vec_pretty(value)?;
    fs::write(&tmp, json)?;

    let mut last_err = None;
    for attempt in 0..10 {
        match fs::rename(&tmp, path) {
            Ok(()) => return Ok(()),
            Err(e) => {
                last_err = Some(e);
                if attempt < 9 {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
            }
        }
    }
    let _ = fs::remove_file(&tmp);
    Err(last_err.unwrap().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_config_atomically() {
        let dir = std::env::temp_dir().join(format!("curb_store_{}", uuid::Uuid::new_v4()));
        let mut cfg = Config::default();
        cfg.presets.steam.community_and_workshop = true;

        save_config(&dir, &cfg).unwrap();
        let loaded = load_config(&dir).unwrap();
        assert_eq!(loaded, cfg);

        let _ = fs::remove_dir_all(&dir);
    }
}
