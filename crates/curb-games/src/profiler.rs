use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::GameTelemetrySnapshot;

/// User-labeled game state during an interactive `curb-cli profile` session.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ProfileState {
    Menu,
    Lobby,
    Playing,
}

impl ProfileState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Menu => "menu",
            Self::Lobby => "lobby",
            Self::Playing => "playing",
        }
    }

    pub fn parse(input: &str) -> Option<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "menu" | "m" | "main" => Some(Self::Menu),
            "lobby" | "l" | "queue" | "postgame" => Some(Self::Lobby),
            "playing" | "p" | "match" | "game" | "ingame" => Some(Self::Playing),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateMarker {
    pub elapsed_secs: f64,
    pub timestamp_utc: DateTime<Utc>,
    pub state: ProfileState,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileSample {
    pub elapsed_secs: f64,
    pub telemetry: GameTelemetrySnapshot,
}

/// Complete recorded profiling session produced by `curb-cli profile`.
///
/// Accounts for human reaction delay when alt-tabbing from the game to the CLI:
/// - `pre_transition_guard_secs` (default `8.0s`): trimmed from the *end* of each
///   labeled segment before the next state marker, because the real in-game state
///   likely changed several seconds before the user typed the new state.
/// - `post_transition_guard_secs` (default `3.0s`): trimmed from the *start* of each
///   segment after a state marker to allow loading/settling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileSession {
    pub app_id: u32,
    pub game_name: String,
    pub started_at_utc: DateTime<Utc>,
    pub pre_transition_guard_secs: f64,
    pub post_transition_guard_secs: f64,
    pub markers: Vec<StateMarker>,
    pub samples: Vec<ProfileSample>,
}

impl ProfileSession {
    pub fn new(app_id: u32, game_name: String) -> Self {
        let now = Utc::now();
        Self {
            app_id,
            game_name,
            started_at_utc: now,
            pre_transition_guard_secs: 8.0,
            post_transition_guard_secs: 3.0,
            markers: vec![StateMarker {
                elapsed_secs: 0.0,
                timestamp_utc: now,
                state: ProfileState::Menu,
                note: Some("initial assumed state".into()),
            }],
            samples: Vec::new(),
        }
    }

    pub fn add_marker(&mut self, elapsed_secs: f64, state: ProfileState, note: Option<String>) {
        self.markers.push(StateMarker {
            elapsed_secs,
            timestamp_utc: Utc::now(),
            state,
            note,
        });
    }

    pub fn add_sample(&mut self, elapsed_secs: f64, telemetry: GameTelemetrySnapshot) {
        self.samples.push(ProfileSample {
            elapsed_secs,
            telemetry,
        });
    }

    /// Analyzes steady-state telemetry per labeled state, trimming human-delay guard bands
    /// around every state transition.
    pub fn analyze(&self) -> ProfileAnalysis {
        let end_elapsed = self
            .samples
            .last()
            .map(|s| s.elapsed_secs)
            .unwrap_or(0.0)
            .max(self.markers.last().map(|m| m.elapsed_secs).unwrap_or(0.0));

        let mut grouped: BTreeMap<ProfileState, Vec<&ProfileSample>> = BTreeMap::new();
        let mut total_trimmed = 0usize;

        for idx in 0..self.markers.len() {
            let start = self.markers[idx].elapsed_secs;
            let state = self.markers[idx].state;
            let end = if idx + 1 < self.markers.len() {
                self.markers[idx + 1].elapsed_secs
            } else {
                end_elapsed
            };

            let duration = (end - start).max(0.0);
            let is_last = idx + 1 == self.markers.len();
            let post_guard = if idx == 0 {
                // Allow initial game launch/process startup to settle.
                self.post_transition_guard_secs
            } else {
                self.post_transition_guard_secs
            };
            let pre_guard = if is_last {
                // User also alt-tabbed at the end to type "done".
                self.pre_transition_guard_secs.min(duration * 0.25)
            } else {
                self.pre_transition_guard_secs
            };

            let (clean_start, clean_end) = if duration > (post_guard + pre_guard + 2.0) {
                (start + post_guard, end - pre_guard)
            } else {
                // Short segment fallback: use the interior middle 50%.
                (start + duration * 0.25, end - duration * 0.25)
            };

            for sample in &self.samples {
                if sample.elapsed_secs >= start && sample.elapsed_secs < end {
                    if sample.telemetry.pids.is_empty() {
                        continue;
                    }
                    if sample.elapsed_secs >= clean_start && sample.elapsed_secs <= clean_end {
                        grouped.entry(state).or_default().push(sample);
                    } else {
                        total_trimmed += 1;
                    }
                }
            }
        }

        let mut state_stats = BTreeMap::new();
        for (state, samples) in grouped {
            state_stats.insert(state, compute_state_stats(&samples));
        }

        let recommendation = compute_recommendation(&state_stats);

        ProfileAnalysis {
            app_id: self.app_id,
            game_name: self.game_name.clone(),
            total_samples: self.samples.len(),
            trimmed_transition_samples: total_trimmed,
            pre_transition_guard_secs: self.pre_transition_guard_secs,
            post_transition_guard_secs: self.post_transition_guard_secs,
            state_stats,
            recommendation,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateStats {
    pub sample_count: usize,
    pub median_udp_sockets: usize,
    pub max_udp_sockets: usize,
    pub median_tcp_conns: usize,
    pub median_bytes_per_sec: u64,
    pub p90_bytes_per_sec: u64,
    pub max_bytes_per_sec: u64,
    pub median_udp_pps: u64,
    pub p90_udp_pps: u64,
    pub unique_remote_udp: Vec<String>,
    pub touched_files: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalibrationRecommendation {
    pub suggested_min_udp_sockets: usize,
    pub suggested_min_bytes_per_sec: u64,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileAnalysis {
    pub app_id: u32,
    pub game_name: String,
    pub total_samples: usize,
    pub trimmed_transition_samples: usize,
    pub pre_transition_guard_secs: f64,
    pub post_transition_guard_secs: f64,
    pub state_stats: BTreeMap<ProfileState, StateStats>,
    pub recommendation: Option<CalibrationRecommendation>,
}

fn compute_state_stats(samples: &[&ProfileSample]) -> StateStats {
    let mut udps: Vec<usize> = samples
        .iter()
        .map(|s| s.telemetry.non_loopback_udp_count())
        .collect();
    let mut tcps: Vec<usize> = samples
        .iter()
        .map(|s| s.telemetry.tcp_endpoints.len())
        .collect();
    let mut bps: Vec<u64> = samples
        .iter()
        .map(|s| s.telemetry.total_bytes_per_sec())
        .collect();
    let mut pps: Vec<u64> = samples
        .iter()
        .map(|s| s.telemetry.udp_packets_per_sec)
        .collect();

    udps.sort_unstable();
    tcps.sort_unstable();
    bps.sort_unstable();
    pps.sort_unstable();

    let mut remotes = BTreeSet::new();
    let mut files = BTreeSet::new();
    for s in samples {
        for u in &s.telemetry.udp_endpoints {
            if let Some(r) = &u.remote_addr {
                remotes.insert(r.clone());
            }
        }
        for f in &s.telemetry.file_activities {
            files.insert(f.path.clone());
        }
    }

    StateStats {
        sample_count: samples.len(),
        median_udp_sockets: percentile_usize(&udps, 50),
        max_udp_sockets: udps.last().copied().unwrap_or(0),
        median_tcp_conns: percentile_usize(&tcps, 50),
        median_bytes_per_sec: percentile_u64(&bps, 50),
        p90_bytes_per_sec: percentile_u64(&bps, 90),
        max_bytes_per_sec: bps.last().copied().unwrap_or(0),
        median_udp_pps: percentile_u64(&pps, 50),
        p90_udp_pps: percentile_u64(&pps, 90),
        unique_remote_udp: remotes.into_iter().take(20).collect(),
        touched_files: files.into_iter().take(20).collect(),
    }
}

fn compute_recommendation(
    stats: &BTreeMap<ProfileState, StateStats>,
) -> Option<CalibrationRecommendation> {
    let playing = stats.get(&ProfileState::Playing)?;
    let idle_bps = stats
        .get(&ProfileState::Lobby)
        .map(|l| l.p90_bytes_per_sec)
        .unwrap_or(0)
        .max(
            stats
                .get(&ProfileState::Menu)
                .map(|m| m.p90_bytes_per_sec)
                .unwrap_or(0),
        );

    let suggested_bps = if playing.median_bytes_per_sec > idle_bps {
        idle_bps + (playing.median_bytes_per_sec - idle_bps) / 2
    } else {
        playing.median_bytes_per_sec.max(1_000)
    };

    let notes = if playing.median_bytes_per_sec > idle_bps.saturating_mul(2).max(500) {
        format!(
            "Strong separation between Playing (median {:.1} KB/s) and Lobby/Menu (p90 {:.1} KB/s).",
            playing.median_bytes_per_sec as f64 / 1024.0,
            idle_bps as f64 / 1024.0
        )
    } else {
        "Close throughput between Lobby and Playing — inspect unique_remote_udp & touched_files in the saved JSON.".into()
    };

    Some(CalibrationRecommendation {
        suggested_min_udp_sockets: playing.median_udp_sockets.max(1),
        suggested_min_bytes_per_sec: suggested_bps,
        notes,
    })
}

fn percentile_u64(sorted: &[u64], pct: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() - 1) * pct) / 100;
    sorted[idx]
}

fn percentile_usize(sorted: &[usize], pct: usize) -> usize {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() - 1) * pct) / 100;
    sorted[idx]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::UdpEndpointSample;

    #[test]
    fn trims_reaction_delay_around_state_transitions() {
        let mut session = ProfileSession::new(976730, "Halo: MCC".into());
        // Menu: 0..30s (low traffic, EXCEPT at 25..29s user entered match before alt-tabbing!)
        for sec in 0..30 {
            let mut snap = GameTelemetrySnapshot::empty(976730);
            snap.pids = vec![1234];
            snap.udp_endpoints = vec![UdpEndpointSample {
                local_port: 3074,
                remote_addr: Some("20.190.1.1:3074".into()),
            }];
            snap.rx_bytes_per_sec = if sec >= 25 { 25_000 } else { 200 };
            session.add_sample(sec as f64, snap);
        }

        // User alt-tabs at t=30s and types "playing"
        session.add_marker(30.0, ProfileState::Playing, None);
        for sec in 30..70 {
            let mut snap = GameTelemetrySnapshot::empty(976730);
            snap.pids = vec![1234];
            snap.udp_endpoints = vec![UdpEndpointSample {
                local_port: 3074,
                remote_addr: Some("20.190.1.1:3074".into()),
            }];
            snap.rx_bytes_per_sec = 25_000;
            session.add_sample(sec as f64, snap);
        }

        let analysis = session.analyze();
        let menu = analysis.state_stats.get(&ProfileState::Menu).unwrap();
        let playing = analysis.state_stats.get(&ProfileState::Playing).unwrap();

        // Because the 8s pre-transition guard trimmed t=22..30s from Menu,
        // the Menu p90 is NOT polluted by the 25_000 B/s match start at t=25..29s!
        assert_eq!(menu.p90_bytes_per_sec, 200);
        assert_eq!(playing.median_bytes_per_sec, 25_000);
        assert!(analysis.trimmed_transition_samples > 0);
    }
}
