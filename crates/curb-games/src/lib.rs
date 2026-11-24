pub mod profiler;
pub mod signals;
pub mod telemetry;
pub mod titles;

use std::collections::HashMap;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// High-level multiplayer match state inferred from external, anti-cheat-safe telemetry.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MatchState {
    /// Player is actively inside a live multiplayer match.
    InMatch,
    /// Player is in menus, pre-game lobby, post-game screen, or matchmaking search.
    LobbyOrMenu,
    /// Detector cannot determine state with confidence.
    Unknown,
}

/// Output of a single [`MatchStateDetector::detect`] evaluation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MatchDetection {
    pub state: MatchState,
    /// Human-readable telemetry explanation shown in Advanced diagnostics.
    pub reason: String,
    /// Recommended debounce duration (seconds) before treating `LobbyOrMenu` as match-ended.
    pub end_debounce_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UdpEndpointSample {
    pub local_port: u16,
    pub remote_addr: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TcpEndpointSample {
    pub local_port: u16,
    pub remote_addr: String,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileActivity {
    pub path: String,
    pub modified_epoch_secs: u64,
    pub size_bytes: u64,
}

/// External, read-only OS telemetry snapshot collected for a running Steam game.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GameTelemetrySnapshot {
    pub timestamp_utc: DateTime<Utc>,
    pub app_id: u32,
    pub pids: Vec<u32>,
    pub udp_socket_count: usize,
    pub udp_endpoints: Vec<UdpEndpointSample>,
    pub tcp_endpoints: Vec<TcpEndpointSample>,
    /// Observed network or per-PID I/O receive rate (bytes/sec) since previous sample.
    pub rx_bytes_per_sec: u64,
    /// Observed network or per-PID I/O transmit rate (bytes/sec) since previous sample.
    pub tx_bytes_per_sec: u64,
    /// Observed UDP packet rate (packets/sec) when available.
    pub udp_packets_per_sec: u64,
    /// Recent file metadata snapshots for game-specific watched directories.
    pub file_activities: Vec<FileActivity>,
}

impl GameTelemetrySnapshot {
    pub fn empty(app_id: u32) -> Self {
        Self {
            timestamp_utc: Utc::now(),
            app_id,
            pids: Vec::new(),
            udp_socket_count: 0,
            udp_endpoints: Vec::new(),
            tcp_endpoints: Vec::new(),
            rx_bytes_per_sec: 0,
            tx_bytes_per_sec: 0,
            udp_packets_per_sec: 0,
            file_activities: Vec::new(),
        }
    }

    pub fn non_loopback_udp_count(&self) -> usize {
        self.udp_endpoints
            .iter()
            .filter(|e| match &e.remote_addr {
                Some(addr) => !addr.starts_with("127.") && !addr.starts_with("[::1]"),
                None => e.local_port > 0,
            })
            .count()
    }

    pub fn total_bytes_per_sec(&self) -> u64 {
        self.rx_bytes_per_sec.saturating_add(self.tx_bytes_per_sec)
    }
}

/// Static metadata describing a first-class game plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirstClassGameInfo {
    pub app_id: u32,
    pub title: &'static str,
    pub plugin_name: &'static str,
    pub signal_summary: &'static str,
    pub default_max_overtime_minutes: u32,
    pub exe_hints: &'static [&'static str],
}

/// Plugin trait implemented by each first-class Steam title.
pub trait MatchStateDetector: Send + Sync {
    fn info(&self) -> FirstClassGameInfo;

    /// Optional extra directories to watch for file activity (relative to user profile / LocalLow / Proton pfx).
    fn watched_relative_paths(&self) -> &'static [&'static str] {
        &[]
    }

    /// Evaluate current match state from external telemetry.
    fn detect(&mut self, telemetry: &GameTelemetrySnapshot) -> MatchDetection;

    /// Reset internal smoothing/hysteresis state when the game process exits.
    fn reset(&mut self);
}

/// Registry of all compiled-in first-class per-title match-state plugins.
pub struct DetectorRegistry {
    detectors: HashMap<u32, Box<dyn MatchStateDetector>>,
}

impl Default for DetectorRegistry {
    fn default() -> Self {
        let mut reg = Self {
            detectors: HashMap::new(),
        };
        for detector in titles::builtin_detectors() {
            reg.register(detector);
        }
        reg
    }
}

impl DetectorRegistry {
    pub fn register(&mut self, detector: Box<dyn MatchStateDetector>) {
        let app_id = detector.info().app_id;
        self.detectors.insert(app_id, detector);
    }

    pub fn is_first_class(&self, app_id: u32) -> bool {
        self.detectors.contains_key(&app_id)
    }

    pub fn info(&self, app_id: u32) -> Option<FirstClassGameInfo> {
        self.detectors.get(&app_id).map(|d| d.info())
    }

    pub fn get_mut(&mut self, app_id: u32) -> Option<&mut Box<dyn MatchStateDetector>> {
        self.detectors.get_mut(&app_id)
    }

    pub fn all_info(&self) -> Vec<FirstClassGameInfo> {
        let mut out: Vec<_> = self.detectors.values().map(|d| d.info()).collect();
        out.sort_by_key(|i| i.app_id);
        out
    }

    /// Resolves a CLI game name alias (e.g. `"halo"`, `"mcc"`, `"astro"`) or numeric AppID.
    pub fn resolve_app_id(&self, query: &str) -> Option<(u32, String)> {
        let q = query.trim();
        if let Ok(id) = q.parse::<u32>() {
            let name = self
                .info(id)
                .map(|i| i.title.to_string())
                .unwrap_or_else(|| format!("Steam App {id}"));
            return Some((id, name));
        }

        let lower = q.to_ascii_lowercase();
        if lower == "halo" || lower == "mcc" || lower.contains("master chief") {
            return Some((
                titles::halo_mcc::APP_ID_HALO_MCC,
                "Halo: The Master Chief Collection".into(),
            ));
        }
        if lower == "astro" || lower.contains("astro party") || lower == "astroparty" {
            return Some((
                titles::astro_party::APP_ID_ASTRO_PARTY_EX,
                "Astro Party EX".into(),
            ));
        }

        for info in self.all_info() {
            if info.title.to_ascii_lowercase().contains(&lower) {
                return Some((info.app_id, info.title.to_string()));
            }
        }
        None
    }
}

/// Resolves platform-specific candidate data directories for a game (e.g. Windows LocalLow or Linux Proton prefix).
pub fn resolve_watched_dirs(
    app_id: u32,
    steam_root: Option<&std::path::Path>,
    relative_paths: &[&str],
) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if relative_paths.is_empty() {
        return out;
    }

    // Windows native user profile
    if let Ok(profile) = std::env::var("USERPROFILE") {
        let base = PathBuf::from(profile);
        for rel in relative_paths {
            let p = base.join(rel);
            if p.exists() {
                out.push(p);
            }
        }
    }

    // Linux Proton compatdata prefix
    if let Some(root) = steam_root {
        let pfx_user = root
            .join("steamapps")
            .join("compatdata")
            .join(app_id.to_string())
            .join("pfx")
            .join("drive_c")
            .join("users")
            .join("steamuser");
        for rel in relative_paths {
            let p = pfx_user.join(rel);
            if p.exists() {
                out.push(p);
            }
        }
    }

    out
}
