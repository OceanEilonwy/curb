use std::fs;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::auth::AuthRecord;
use crate::config::Config;
use crate::playtime::UsageLedger;
use crate::Result;

/// Default system data directory on Linux (`curb-service` / `sudo curb-cli`).
pub const LINUX_SYSTEM_DATA_DIR: &str = "/var/lib/curb";

/// Default system data directory on Windows (`CurbService` / elevated `curb-cli`).
pub const WINDOWS_SYSTEM_DATA_DIR: &str = r"C:\ProgramData\Curb";

pub fn config_path(data_dir: &Path) -> PathBuf {
    data_dir.join("config.json")
}

pub fn auth_path(data_dir: &Path) -> PathBuf {
    data_dir.join("auth.json")
}

pub fn dns_backup_path(data_dir: &Path) -> PathBuf {
    data_dir.join("dns_backup.json")
}

pub fn usage_path(data_dir: &Path) -> PathBuf {
    data_dir.join("usage.json")
}

pub fn sync_config_path(data_dir: &Path) -> PathBuf {
    data_dir.join("sync.json")
}

pub fn peer_identity_path(data_dir: &Path) -> PathBuf {
    data_dir.join("peer_identity.json")
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

pub fn load_usage(data_dir: &Path) -> Result<UsageLedger> {
    let path = usage_path(data_dir);
    if !path.exists() {
        return Ok(UsageLedger::default());
    }
    Ok(read_json(&path)?)
}

pub fn save_usage(data_dir: &Path, ledger: &UsageLedger) -> Result<()> {
    let path = usage_path(data_dir);
    write_json_atomic(&path, ledger)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub fn load_auth(data_dir: &Path) -> Result<Option<AuthRecord>> {
    let path = auth_path(data_dir);
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(read_json(&path)?))
}

pub fn save_auth(data_dir: &Path, record: &AuthRecord) -> Result<()> {
    let path = auth_path(data_dir);
    write_json_atomic(&path, record)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub fn load_sync_config(data_dir: &Path) -> Result<crate::sync::RemoteSyncConfig> {
    let path = sync_config_path(data_dir);
    if !path.exists() {
        let default_name = default_hostname();
        let cfg = crate::sync::RemoteSyncConfig::new_default(default_name);
        let _ = save_sync_config(data_dir, &cfg);
        return Ok(cfg);
    }
    read_json(&path)
}

pub fn save_sync_config(data_dir: &Path, cfg: &crate::sync::RemoteSyncConfig) -> Result<()> {
    let path = sync_config_path(data_dir);
    write_json_atomic(&path, cfg)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn default_hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "This PC".into())
}

fn own_writes() -> &'static std::sync::Mutex<std::collections::HashMap<PathBuf, std::time::SystemTime>>
{
    static OWN: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<PathBuf, std::time::SystemTime>>,
    > = std::sync::OnceLock::new();
    OWN.get_or_init(Default::default)
}

fn record_own_write(path: &Path) {
    if let Ok(m) = fs::metadata(path).and_then(|m| m.modified()) {
        if let Ok(mut map) = own_writes().lock() {
            map.insert(path.to_path_buf(), m);
        }
    }
}

/// Returns the file's current modification time (used to seed [`external_change`]).
pub fn file_mtime(path: &Path) -> Option<std::time::SystemTime> {
    fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// Returns `true` when `path` was modified since `last_seen` by something other than this
/// process's own [`write_json_atomic`] (e.g. `curb-cli` editing config while the service
/// is running). Updates `last_seen`.
pub fn external_change(path: &Path, last_seen: &mut Option<std::time::SystemTime>) -> bool {
    let Some(m) = file_mtime(path) else {
        return false;
    };
    if *last_seen == Some(m) {
        return false;
    }
    *last_seen = Some(m);
    own_writes()
        .lock()
        .map(|map| map.get(path) != Some(&m))
        .unwrap_or(true)
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
            Ok(()) => {
                record_own_write(path);
                return Ok(());
            }
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
    fn external_change_ignores_own_writes_but_detects_foreign_ones() {
        let dir = std::env::temp_dir().join(format!("curb_store_ext_{}", uuid::Uuid::new_v4()));
        let cfg = Config::default();
        save_config(&dir, &cfg).unwrap();
        let path = config_path(&dir);
        let mut seen = file_mtime(&path);

        // Our own write is not an external change.
        std::thread::sleep(std::time::Duration::from_millis(20));
        save_config(&dir, &cfg).unwrap();
        assert!(!external_change(&path, &mut seen));

        // A write by "another process" (plain fs::write, not recorded) is.
        std::thread::sleep(std::time::Duration::from_millis(20));
        fs::write(&path, fs::read(&path).unwrap()).unwrap();
        assert!(external_change(&path, &mut seen));
        assert!(!external_change(&path, &mut seen));
        let _ = fs::remove_dir_all(&dir);
    }

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
