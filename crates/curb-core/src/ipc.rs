use std::collections::VecDeque;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::{BaselinePolicy, Config, EnforcementMode, Rule};
use crate::presets::SteamPresetConfig;
use crate::steam::DiscoveredSteamGame;
use crate::verify::BinaryIdentity;

/// Named pipe path used on Windows between `curb-app` and `curb-service`.
pub const WINDOWS_PIPE_NAME: &str = r"\\.\pipe\curb-ipc";

/// System-wide Unix domain socket path used by `curb-service` on Linux (systemd).
pub const LINUX_UNIX_SOCKET_PATH: &str = "/run/curb/ipc.sock";

/// Fallback Unix socket path used during unprivileged non-Windows development.
pub const DEV_UNIX_SOCKET_PATH: &str = "/tmp/curb-ipc.sock";

/// Maximum number of unique `(app, destination)` blocked entries retained in memory.
pub const MAX_BLOCKED_HISTORY: usize = 100;

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

/// Records a blocked network/DNS attempt grouped by `(app_name, destination)`
/// (case-insensitive) and ordered by most recently attempted first.
///
/// If an entry for the same `(app_name, destination)` already exists, it is
/// moved to the front with its `timestamp` updated to the latest attempt while
/// preserving its `id` (so in-flight UI actions remain valid) and keeping
/// richer executable metadata if the newer event has no file path. Otherwise,
/// the new entry is inserted at the front and the least-recently-attempted
/// entry is evicted once `max_len` is reached.
pub fn record_grouped_blocked_event(
    events: &mut VecDeque<BlockedEvent>,
    event: BlockedEvent,
    max_len: usize,
) {
    if max_len == 0 {
        events.clear();
        return;
    }

    if let Some(pos) = events.iter().position(|existing| {
        existing.app_name.eq_ignore_ascii_case(&event.app_name)
            && existing.destination.eq_ignore_ascii_case(&event.destination)
    }) {
        let mut existing = events.remove(pos).unwrap();
        existing.timestamp = existing.timestamp.max(event.timestamp);
        existing.is_steam_community = existing.is_steam_community || event.is_steam_community;
        if !event.path.is_empty() {
            existing.exe = event.exe;
            existing.path = event.path;
            existing.signed = event.signed;
            existing.signer = event.signer;
        } else if existing.path.is_empty() {
            existing.exe = event.exe;
            existing.signed = event.signed;
            existing.signer = event.signer;
        }
        events.push_front(existing);
        return;
    }

    while events.len() >= max_len {
        events.pop_back();
    }
    events.push_front(event);
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

    fn make_event(
        app_name: &str,
        exe: &str,
        path: &str,
        destination: &str,
        ts: DateTime<Utc>,
    ) -> BlockedEvent {
        BlockedEvent {
            id: Uuid::new_v4(),
            timestamp: ts,
            app_name: app_name.into(),
            exe: exe.into(),
            path: path.into(),
            destination: destination.into(),
            signed: !path.is_empty(),
            signer: None,
            is_steam_community: destination.to_ascii_lowercase().contains("steamcommunity.com"),
        }
    }

    #[test]
    fn groups_by_app_and_destination_updating_last_attempted_and_order() {
        let base = Utc::now();
        let mut events = VecDeque::new();

        let edge_yt = make_event(
            "Microsoft Edge",
            "msedge.exe",
            r"C:\Edge\msedge.exe",
            "youtube.com",
            base,
        );
        let original_id = edge_yt.id;
        record_grouped_blocked_event(&mut events, edge_yt, 100);

        let discord = make_event(
            "Discord",
            "Discord.exe",
            r"C:\Discord\Discord.exe",
            "discord.gg",
            base + chrono::Duration::seconds(10),
        );
        record_grouped_blocked_event(&mut events, discord, 100);

        // Same app, different destination -> separate entry.
        let edge_reddit = make_event(
            "Microsoft Edge",
            "msedge.exe",
            r"C:\Edge\msedge.exe",
            "reddit.com",
            base + chrono::Duration::seconds(20),
        );
        record_grouped_blocked_event(&mut events, edge_reddit, 100);
        assert_eq!(events.len(), 3);

        // Repeat of (Microsoft Edge, youtube.com) with different casing -> grouped,
        // moved to front, timestamp updated, id preserved.
        let repeat_ts = base + chrono::Duration::seconds(45);
        let edge_yt_repeat = make_event(
            "microsoft edge",
            "msedge.exe",
            r"C:\Edge\msedge.exe",
            "YOUTUBE.COM",
            repeat_ts,
        );
        record_grouped_blocked_event(&mut events, edge_yt_repeat, 100);

        assert_eq!(events.len(), 3);
        assert_eq!(events[0].id, original_id);
        assert_eq!(events[0].app_name, "Microsoft Edge");
        assert_eq!(events[0].destination, "youtube.com");
        assert_eq!(events[0].timestamp, repeat_ts);
        assert_eq!(events[1].destination, "reddit.com");
        assert_eq!(events[2].app_name, "Discord");
    }

    #[test]
    fn preserves_executable_path_when_dns_only_event_updates_group() {
        let base = Utc::now();
        let mut events = VecDeque::new();

        let with_path = make_event(
            "Steam Community",
            "steamwebhelper.exe",
            r"C:\Steam\steamwebhelper.exe",
            "steamcommunity.com",
            base,
        );
        record_grouped_blocked_event(&mut events, with_path, 100);

        let dns_only = make_event(
            "Steam Community",
            "dnscache",
            "",
            "steamcommunity.com",
            base + chrono::Duration::seconds(30),
        );
        record_grouped_blocked_event(&mut events, dns_only, 100);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].path, r"C:\Steam\steamwebhelper.exe");
        assert_eq!(events[0].exe, "steamwebhelper.exe");
        assert_eq!(events[0].timestamp, base + chrono::Duration::seconds(30));
    }

    #[test]
    fn evicts_least_recently_attempted_entry_at_cap() {
        let base = Utc::now();
        let mut events = VecDeque::new();

        record_grouped_blocked_event(&mut events, make_event("AppA", "a.exe", "", "a.com", base), 2);
        record_grouped_blocked_event(
            &mut events,
            make_event("AppB", "b.exe", "", "b.com", base + chrono::Duration::seconds(1)),
            2,
        );
        // Refresh AppA so AppB becomes the least recently attempted.
        record_grouped_blocked_event(
            &mut events,
            make_event("AppA", "a.exe", "", "a.com", base + chrono::Duration::seconds(2)),
            2,
        );
        // Adding AppC should evict AppB, keeping AppC and AppA.
        record_grouped_blocked_event(
            &mut events,
            make_event("AppC", "c.exe", "", "c.com", base + chrono::Duration::seconds(3)),
            2,
        );

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].app_name, "AppC");
        assert_eq!(events[1].app_name, "AppA");
    }
}
