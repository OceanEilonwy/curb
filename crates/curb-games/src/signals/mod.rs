use chrono::{DateTime, Utc};

use crate::MatchState;

/// Reusable hysteresis tracker that turns noisy per-tick "active match signal" booleans
/// into stable `InMatch` / `LobbyOrMenu` transitions.
///
/// - Requires `min_sustain_secs` of continuous active signal to enter `InMatch`
///   (avoids false positives from brief matchmaking QoS pings).
/// - Requires `end_debounce_secs` of continuous inactive signal to leave `InMatch`
///   (survives brief host migrations, map loads, or lag spikes).
#[derive(Debug, Clone)]
pub struct SustainedActivityTracker {
    pub min_sustain_secs: u64,
    pub end_debounce_secs: u64,
    in_match: bool,
    active_since: Option<DateTime<Utc>>,
    inactive_since: Option<DateTime<Utc>>,
}

impl SustainedActivityTracker {
    pub fn new(min_sustain_secs: u64, end_debounce_secs: u64) -> Self {
        Self {
            min_sustain_secs,
            end_debounce_secs,
            in_match: false,
            active_since: None,
            inactive_since: None,
        }
    }

    pub fn reset(&mut self) {
        self.in_match = false;
        self.active_since = None;
        self.inactive_since = None;
    }

    pub fn update(&mut self, signal_active: bool, now: DateTime<Utc>) -> MatchState {
        if signal_active {
            self.inactive_since = None;
            let since = *self.active_since.get_or_insert(now);
            if !self.in_match && (now - since).num_seconds() >= self.min_sustain_secs as i64 {
                self.in_match = true;
            }
        } else {
            self.active_since = None;
            if self.in_match {
                let since = *self.inactive_since.get_or_insert(now);
                if (now - since).num_seconds() >= self.end_debounce_secs as i64 {
                    self.in_match = false;
                }
            }
        }

        if self.in_match {
            MatchState::InMatch
        } else {
            MatchState::LobbyOrMenu
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn requires_sustain_to_enter_and_debounce_to_exit() {
        let mut tracker = SustainedActivityTracker::new(6, 20);
        let t0 = Utc::now();

        // Brief 2-second QoS burst should NOT trigger InMatch
        assert_eq!(tracker.update(true, t0), MatchState::LobbyOrMenu);
        assert_eq!(
            tracker.update(true, t0 + Duration::seconds(2)),
            MatchState::LobbyOrMenu
        );
        assert_eq!(
            tracker.update(false, t0 + Duration::seconds(4)),
            MatchState::LobbyOrMenu
        );

        // Sustained 6s+ activity enters InMatch
        let t1 = t0 + Duration::seconds(10);
        assert_eq!(tracker.update(true, t1), MatchState::LobbyOrMenu);
        assert_eq!(
            tracker.update(true, t1 + Duration::seconds(6)),
            MatchState::InMatch
        );

        // 10s dip stays InMatch (within 20s debounce)
        assert_eq!(
            tracker.update(false, t1 + Duration::seconds(10)),
            MatchState::InMatch
        );
        assert_eq!(
            tracker.update(false, t1 + Duration::seconds(25)),
            MatchState::InMatch
        );

        // 20s continuous inactivity exits to LobbyOrMenu
        assert_eq!(
            tracker.update(false, t1 + Duration::seconds(30)),
            MatchState::LobbyOrMenu
        );
    }
}
