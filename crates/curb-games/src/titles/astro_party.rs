use crate::signals::SustainedActivityTracker;
use crate::{FirstClassGameInfo, GameTelemetrySnapshot, MatchDetection, MatchState, MatchStateDetector};

/// Steam AppID for Astro Party EX.
pub const APP_ID_ASTRO_PARTY_EX: u32 = 4178190;

/// Calibration thresholds for Astro Party EX (tunable via `curb-cli profile astro`).
#[derive(Debug, Clone)]
pub struct AstroPartyThresholds {
    pub min_udp_sockets: usize,
    pub min_bytes_per_sec: u64,
    pub min_udp_pps: u64,
    pub min_sustain_secs: u64,
    pub end_debounce_secs: u64,
}

impl Default for AstroPartyThresholds {
    fn default() -> Self {
        Self {
            min_udp_sockets: 1,
            min_bytes_per_sec: 1_000,
            min_udp_pps: 8,
            min_sustain_secs: 4,
            end_debounce_secs: 10,
        }
    }
}

/// First-class match-state detector for Astro Party EX.
///
/// Tracks Steam Networking Sockets / UDP relay activity cadence to distinguish
/// active Online PvP matches from the main menu and lobby screen.
pub struct AstroPartyExDetector {
    thresholds: AstroPartyThresholds,
    tracker: SustainedActivityTracker,
}

impl AstroPartyExDetector {
    pub fn new() -> Self {
        Self::with_thresholds(AstroPartyThresholds::default())
    }

    pub fn with_thresholds(thresholds: AstroPartyThresholds) -> Self {
        let tracker = SustainedActivityTracker::new(
            thresholds.min_sustain_secs,
            thresholds.end_debounce_secs,
        );
        Self {
            thresholds,
            tracker,
        }
    }
}

impl Default for AstroPartyExDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl MatchStateDetector for AstroPartyExDetector {
    fn info(&self) -> FirstClassGameInfo {
        FirstClassGameInfo {
            app_id: APP_ID_ASTRO_PARTY_EX,
            title: "Astro Party EX",
            plugin_name: "Astro Party EX Plugin",
            signal_summary: "Steam Networking UDP relay flow cadence",
            default_max_overtime_minutes: 15,
            exe_hints: &["AstroPartyEX.exe", "AstroParty.exe", "Astro Party EX.exe"],
        }
    }

    fn watched_relative_paths(&self) -> &'static [&'static str] {
        &["AppData/LocalLow/Wild Rooster", "AppData/Roaming/AstroPartyEX"]
    }

    fn detect(&mut self, telemetry: &GameTelemetrySnapshot) -> MatchDetection {
        let udp_count = telemetry.non_loopback_udp_count();
        let bps = telemetry.total_bytes_per_sec();
        let pps = telemetry.udp_packets_per_sec;

        let signal_active = udp_count >= self.thresholds.min_udp_sockets
            && (pps >= self.thresholds.min_udp_pps || bps >= self.thresholds.min_bytes_per_sec);

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
    }
}
