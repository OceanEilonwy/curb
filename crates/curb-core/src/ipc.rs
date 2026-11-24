use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::{BaselinePolicy, Config, EnforcementMode, Rule};
use crate::presets::SteamPresetConfig;
use crate::steam::DiscoveredSteamGame;
use crate::verify::BinaryIdentity;

/// Named pipe path used on Windows between `curb-app` and `curb-service`.
pub const WINDOWS_PIPE_NAME: &str = r"\\.\pipe\curb-ipc";

/// Unix socket path used during non-Windows development.
pub const DEV_UNIX_SOCKET_PATH: &str = "/tmp/curb-ipc.sock";

/// A grouped running application (Task Manager / Activity Monitor style)
/// returned to the "Allow App or Game" picker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunningAppInfo {
    pub key: String,
    pub name: String,
    pub exe: String,
    pub path: String,
    pub process_count: u32,
    pub background: bool,
    pub tried_connect: bool,
    pub tried_host: Option<String>,
    pub signed: bool,
    pub signer: Option<String>,
    pub sha256: String,
}

/// A recent blocked network or DNS attempt shown in the Blocked tab.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub app_name: String,
    pub exe: String,
    pub path: String,
    pub destination: String,
    pub signed: bool,
    pub signer: Option<String>,
    pub is_steam_community: bool,
}

/// Indicates which protection architecture Curb is currently running in.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionTier {
    #[default]
    Unconfigured,
    /// LocalSystem Windows Service + WFP default-deny across all adapters.
    FullService,
    /// Per-user local proxy mode requiring zero Windows Administrator privileges.
    StandardUser,
}

/// Snapshot of service state returned on initial load and updates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceSnapshot {
    pub config: Config,
    pub password_configured: bool,
    pub blocked_events: Vec<BlockedEvent>,
    pub active_wfp_filters: usize,
    #[serde(default)]
    pub protection_tier: ProtectionTier,
    #[serde(default)]
    pub service_version: String,
}

/// Requests sent from `curb-app` (or `curb-cli`) to `curb-service`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum IpcRequest {
    // --- Read-only operations (no session token required) ---
    GetSnapshot,
    ListRunningApps {
        /// PIDs of processes with visible top-level windows in the caller's interactive
        /// desktop session. Needed because `CurbService` runs in isolated Session 0 on
        /// Windows and cannot observe user desktop windows via `EnumWindows`.
        #[serde(default)]
        visible_pids: Option<Vec<u32>>,
    },
    ListSteamGames,
    InspectExecutable {
        path: String,
    },

    // --- Authentication ---
    Unlock {
        password: String,
    },
    Lock {
        token: String,
    },

    // --- Mutating operations (require valid admin session token) ---
    SetMode {
        token: String,
        mode: EnforcementMode,
    },
    UpdateSteamPreset {
        token: String,
        steam: SteamPresetConfig,
    },
    UpdateBaseline {
        token: String,
        baseline: BaselinePolicy,
    },
    UpsertRule {
        token: String,
        rule: Rule,
    },
    DeleteRule {
        token: String,
        id: Uuid,
    },
    ChangePassword {
        token: String,
        current_password: String,
        new_password: String,
    },
}

/// Responses returned by `curb-service`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum IpcResponse {
    Snapshot {
        data: ServiceSnapshot,
    },
    RunningApps {
        apps: Vec<RunningAppInfo>,
    },
    SteamGames {
        games: Vec<DiscoveredSteamGame>,
    },
    Inspected {
        identity: BinaryIdentity,
    },
    Unlocked {
        token: String,
    },
    Ok,
    Error {
        message: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_running_apps_deserializes_with_and_without_visible_pids() {
        let legacy: IpcRequest = serde_json::from_str(r#"{"op":"list_running_apps"}"#).unwrap();
        assert!(matches!(
            legacy,
            IpcRequest::ListRunningApps { visible_pids: None }
        ));

        let with_pids: IpcRequest =
            serde_json::from_str(r#"{"op":"list_running_apps","visible_pids":[101,202]}"#).unwrap();
        assert!(matches!(
            with_pids,
            IpcRequest::ListRunningApps {
                visible_pids: Some(ref pids)
            } if pids == &[101, 202]
        ));

        let empty_pids: IpcRequest =
            serde_json::from_str(r#"{"op":"list_running_apps","visible_pids":[]}"#).unwrap();
        assert!(matches!(
            empty_pids,
            IpcRequest::ListRunningApps {
                visible_pids: Some(ref pids)
            } if pids.is_empty()
        ));
    }
}
