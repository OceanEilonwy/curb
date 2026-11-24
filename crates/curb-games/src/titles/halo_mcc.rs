use crate::signals::SustainedActivityTracker;
use crate::{FirstClassGameInfo, GameTelemetrySnapshot, MatchDetection, MatchState, MatchStateDetector};

/// Steam AppID for Halo: The Master Chief Collection.
pub const APP_ID_HALO_MCC: u32 = 976730;

/// Calibration thresholds for Halo: MCC (tunable via `curb-cli profile halo`).
#[derive(Debug, Clone)]
pub struct HaloMccThresholds {
    /// Minimum non-loopback UDP sockets bound by MCC during an active match.
    pub min_udp_sockets: usize,
    /// Minimum sustained bytes/sec (network/IO) indicating active dedicated-server gameplay.
    pub min_bytes_per_sec: u64,
    /// Minimum UDP packets/sec when packet counters are available.
    pub min_udp_pps: u64,
    /// Seconds of sustained signal before entering `InMatch`.
    pub min_sustain_secs: u64,
    /// Seconds of idle signal before transitioning `InMatch -> LobbyOrMenu`.
    pub end_debounce_secs: u64,
}

impl Default for HaloMccThresholds {
    fn default() -> Self {
        Self {
            min_udp_sockets: 1,
            min_bytes_per_sec: 1_500,
            min_udp_pps: 10,
            min_sustain_secs: 6,
            end_debounce_secs: 20,
        }
    }
}

/// First-class EAC-safe match-state detector for Halo: The Master Chief Collection.
///
/// Observes external per-PID UDP dedicated-server flow cadence and optional
/// `AppData\LocalLow\MCC\Temporary` activity without ever touching game memory.
pub struct HaloMccDetector {
    thresholds: HaloMccThresholds,
    tracker: SustainedActivityTracker,
    last_temp_mtime: u64,
}

impl HaloMccDetector {
    pub fn new() -> Self {
        Self::with_thresholds(HaloMccThresholds::default())
    }

    pub fn with_thresholds(thresholds: HaloMccThresholds) -> Self {
        let tracker = SustainedActivityTracker::new(
            thresholds.min_sustain_secs,
            thresholds.end_debounce_secs,
        );
        Self {
            thresholds,
            tracker,
            last_temp_mtime: 0,
        }
    }
}

impl Default for HaloMccDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl MatchStateDetector for HaloMccDetector {
    fn info(&self) -> FirstClassGameInfo {
        FirstClassGameInfo {
            app_id: APP_ID_HALO_MCC,
            title: "Halo: The Master Chief Collection",
            plugin_name: "Halo: MCC Plugin",
            signal_summary: "Azure UDP match flow + MCC Temporary film activity (EAC-safe)",
            default_max_overtime_minutes: 30,
            exe_hints: &["MCC-Win64-Shipping.exe", "mcclauncher.exe"],
        }
    }

    fn watched_relative_paths(&self) -> &'static [&'static str] {
        &["AppData/LocalLow/MCC/Temporary", "AppData/LocalLow/MCC/Saved"]
    }

    fn detect(&mut self, telemetry: &GameTelemetrySnapshot) -> MatchDetection {
        let udp_count = telemetry.non_loopback_udp_count();
        let bps = telemetry.total_bytes_per_sec();
        let pps = telemetry.udp_packets_per_sec;

        // Check whether MCC's Temporary folder saw recent writes (active Theater film recording).
        let newest_temp_mtime = telemetry
            .file_activities
            .iter()
            .filter(|f| f.path.to_ascii_lowercase().contains("temporary"))
            .map(|f| f.modified_epoch_secs)
            .max()
            .unwrap_or(0);
        let temp_recently_active = newest_temp_mtime > self.last_temp_mtime
            && telemetry.timestamp_utc.timestamp().unsigned_abs().saturating_sub(newest_temp_mtime) <= 15;
        if newest_temp_mtime > self.last_temp_mtime {
            self.last_temp_mtime = newest_temp_mtime;
        }

        let udp_flow_active = udp_count >= self.thresholds.min_udp_sockets
            && (pps >= self.thresholds.min_udp_pps || bps >= self.thresholds.min_bytes_per_sec);

        let signal_active = udp_flow_active || (udp_count >= 1 && temp_recently_active);
        let state = self.tracker.update(signal_active, telemetry.timestamp_utc);

        let reason = match state {
            MatchState::InMatch => format!(
                "InMatch · {} UDP socket(s), {:.1} KB/s{}",
                udp_count,
                bps as f64 / 1024.0,
                if pps > 0 {
                    format!(", {pps} pkt/s")
                } else {
                    String::new()
                }
            ),
            MatchState::LobbyOrMenu => format!(
                "LobbyOrMenu · {} UDP socket(s), {:.1} KB/s",
                udp_count,
                bps as f64 / 1024.0
            ),
            MatchState::Unknown => "Unknown".into(),
        };

        MatchDetection {
            state,
            reason,
            end_debounce_secs: self.thresholds.end_debounce_secs,
        }
    }

    fn reset(&mut self) {
        self.tracker.reset();
        self.last_temp_mtime = 0;
    }
}
