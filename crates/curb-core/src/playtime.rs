use std::collections::HashMap;

use chrono::{DateTime, Datelike, Local};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

fn default_true() -> bool {
    true
}

fn default_max_overtime_minutes() -> u32 {
    30
}

/// Per-rule playtime limit configuration attached to a [`crate::config::Rule`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PlaytimeLimitConfig {
    pub enabled: bool,
    pub budget: PlaytimeBudget,
    /// When `true` and a first-class match-state plugin exists for this game,
    /// Curb delays cutting internet access until the active match finishes.
    #[serde(default = "default_true")]
    pub wait_for_match_end: bool,
    /// Hard safety ceiling on overtime while waiting for a match to finish.
    #[serde(default = "default_max_overtime_minutes")]
    pub max_overtime_minutes: u32,
    /// Deduct overtime spent finishing a match from the next day's budget.
    #[serde(default = "default_true")]
    pub carry_over_debt: bool,
}

impl Default for PlaytimeLimitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            budget: PlaytimeBudget::Daily { hours: 2.0 },
            wait_for_match_end: true,
            max_overtime_minutes: default_max_overtime_minutes(),
            carry_over_debt: true,
        }
    }
}

/// Budget specification for a game's playtime limit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum PlaytimeBudget {
    /// Simple daily cap in hours (fractional hours allowed, e.g. `1.5`).
    Daily { hours: f32 },
    /// Simple weekly cap in hours.
    Weekly { hours: f32 },
    /// Natural-language AND rule set, e.g. `"5h per day, 10h per week, except sunday"`.
    Custom {
        expression: String,
        #[serde(default)]
        parsed: CustomBudgetPolicy,
    },
}

impl PlaytimeBudget {
    /// Returns the effective structured policy (caps + exempt weekdays) for this budget.
    pub fn effective_policy(&self) -> CustomBudgetPolicy {
        match self {
            Self::Daily { hours } => CustomBudgetPolicy {
                caps: vec![IntervalCap {
                    minutes: ((*hours).max(0.0) * 60.0).round() as u32,
                    window: CapWindow::Daily,
                }],
                exempt_weekdays: Vec::new(),
            },
            Self::Weekly { hours } => CustomBudgetPolicy {
                caps: vec![IntervalCap {
                    minutes: ((*hours).max(0.0) * 60.0).round() as u32,
                    window: CapWindow::Weekly,
                }],
                exempt_weekdays: Vec::new(),
            },
            Self::Custom { expression, parsed } => {
                if !parsed.caps.is_empty() || !parsed.exempt_weekdays.is_empty() {
                    parsed.clone()
                } else {
                    parse_custom_budget(expression).unwrap_or_default()
                }
            }
        }
    }
}

/// Parsed set of AND constraints and day-of-week exemptions.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CustomBudgetPolicy {
    /// All caps apply simultaneously (logical AND).
    pub caps: Vec<IntervalCap>,
    /// Exempt weekdays (`0 = Sunday .. 6 = Saturday`).
    pub exempt_weekdays: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntervalCap {
    pub minutes: u32,
    pub window: CapWindow,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CapWindow {
    Daily,
    Weekly,
    RollingHours { hours: u32 },
}

/// Parses a human-friendly custom playtime expression into a [`CustomBudgetPolicy`].
///
/// Supported examples:
/// - `"5h per day, 10h per week, except sunday"`
/// - `"1.5h/day, 8h/week, except sat, sun"`
/// - `"90m daily and 45m per 4h"`
/// - `"2 hours per day, except weekends"`
pub fn parse_custom_budget(input: &str) -> std::result::Result<CustomBudgetPolicy, String> {
    let mut policy = CustomBudgetPolicy::default();
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("Budget expression cannot be empty".into());
    }

    // Split on commas or standalone " and ".
    let mut raw_clauses = Vec::new();
    for part in trimmed.split(',') {
        let mut current = String::new();
        let tokens: Vec<&str> = part.split_whitespace().collect();
        for tok in tokens {
            if tok.eq_ignore_ascii_case("and") && !current.is_empty() {
                raw_clauses.push(current.trim().to_string());
                current.clear();
            } else {
                if !current.is_empty() {
                    current.push(' ');
                }
                current.push_str(tok);
            }
        }
        if !current.trim().is_empty() {
            raw_clauses.push(current.trim().to_string());
        }
    }

    let mut in_except_list = false;
    for clause in raw_clauses {
        let lower = clause.to_ascii_lowercase();

        if let Some(rest) = lower.strip_prefix("except ") {
            in_except_list = true;
            parse_weekday_list(rest.trim(), &mut policy.exempt_weekdays)?;
            continue;
        }

        // Allow comma-separated weekdays immediately following an `except` clause,
        // e.g. `"5h per day, except sat, sun"`.
        if in_except_list && parse_weekday_list(&lower, &mut policy.exempt_weekdays).is_ok() {
            continue;
        }
        in_except_list = false;

        let cap = parse_cap_clause(&lower).map_err(|_| format!("Unrecognized rule: \"{clause}\""))?;
        policy.caps.push(cap);
    }

    if policy.caps.is_empty() {
        return Err("At least one time limit is required (e.g. \"2h per day\")".into());
    }

    policy.exempt_weekdays.sort_unstable();
    policy.exempt_weekdays.dedup();
    Ok(policy)
}

fn parse_weekday_list(text: &str, out: &mut Vec<u8>) -> std::result::Result<(), String> {
    let mut matched_any = false;
    for token in text.split(|c: char| c.is_whitespace() || c == '/' || c == '&') {
        let t = token.trim().trim_matches(',');
        if t.is_empty() || t == "and" {
            continue;
        }
        match t {
            "sun" | "sunday" | "sundays" => {
                out.push(0);
                matched_any = true;
            }
            "mon" | "monday" | "mondays" => {
                out.push(1);
                matched_any = true;
            }
            "tue" | "tues" | "tuesday" | "tuesdays" => {
                out.push(2);
                matched_any = true;
            }
            "wed" | "wednesday" | "wednesdays" => {
                out.push(3);
                matched_any = true;
            }
            "thu" | "thur" | "thurs" | "thursday" | "thursdays" => {
                out.push(4);
                matched_any = true;
            }
            "fri" | "friday" | "fridays" => {
                out.push(5);
                matched_any = true;
            }
            "sat" | "saturday" | "saturdays" => {
                out.push(6);
                matched_any = true;
            }
            "weekend" | "weekends" => {
                out.push(0);
                out.push(6);
                matched_any = true;
            }
            "weekday" | "weekdays" => {
                out.extend_from_slice(&[1, 2, 3, 4, 5]);
                matched_any = true;
            }
            _ => return Err(format!("Unknown weekday \"{t}\"")),
        }
    }
    if matched_any {
        Ok(())
    } else {
        Err("Expected weekday name after 'except'".into())
    }
}

fn parse_cap_clause(lower: &str) -> std::result::Result<IntervalCap, String> {
    // Normalize "/" into " per " so "5h/day" and "5h per day" follow the same path.
    let normalized = lower.replace('/', " per ");
    let tokens: Vec<&str> = normalized.split_whitespace().collect();
    if tokens.is_empty() {
        return Err("empty clause".into());
    }

    // Parse leading duration token(s): e.g. "5h", "1.5", "hours", "90m"
    let (minutes, next_idx) = parse_duration_tokens(&tokens)?;
    if minutes == 0 {
        return Err("duration must be positive".into());
    }

    let rest = &tokens[next_idx..];
    let rest = match rest.first().copied() {
        Some("per") | Some("every") => &rest[1..],
        _ => rest,
    };

    let window = match rest {
        ["day"] | ["daily"] | ["a", "day"] | ["1", "day"] => CapWindow::Daily,
        ["week"] | ["weekly"] | ["a", "week"] | ["1", "week"] => CapWindow::Weekly,
        [rolling] => {
            let h = parse_hours_token(rolling)?;
            CapWindow::RollingHours { hours: h }
        }
        [num, unit] if is_hour_unit(unit) => {
            let h: u32 = num.parse().map_err(|_| "invalid rolling hours")?;
            if h == 0 {
                return Err("rolling hours must be > 0".into());
            }
            CapWindow::RollingHours { hours: h }
        }
        _ => return Err("unrecognized interval window".into()),
    };

    Ok(IntervalCap { minutes, window })
}

fn parse_duration_tokens(tokens: &[&str]) -> std::result::Result<(u32, usize), String> {
    let first = tokens[0];
    // Inline unit form: "5h", "1.5h", "90m", "30min"
    let split_pos = first
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(first.len());

    if split_pos > 0 && split_pos < first.len() {
        let num: f32 = first[..split_pos].parse().map_err(|_| "invalid number")?;
        let unit = &first[split_pos..];
        let mins = scale_duration(num, unit)?;
        return Ok((mins, 1));
    }

    // Separate unit form: "5 hours", "90 mins"
    if tokens.len() >= 2 {
        let num: f32 = first.parse().map_err(|_| "invalid number")?;
        let mins = scale_duration(num, tokens[1])?;
        return Ok((mins, 2));
    }

    Err("missing duration unit".into())
}

fn scale_duration(num: f32, unit: &str) -> std::result::Result<u32, String> {
    if is_hour_unit(unit) {
        Ok((num * 60.0).round() as u32)
    } else if is_minute_unit(unit) {
        Ok(num.round() as u32)
    } else {
        Err(format!("unknown duration unit '{unit}'"))
    }
}

fn parse_hours_token(tok: &str) -> std::result::Result<u32, String> {
    let split_pos = tok.find(|c: char| !c.is_ascii_digit()).unwrap_or(tok.len());
    if split_pos == 0 || split_pos == tok.len() {
        return Err("invalid rolling hours token".into());
    }
    let h: u32 = tok[..split_pos].parse().map_err(|_| "invalid hours")?;
    let unit = &tok[split_pos..];
    if h > 0 && is_hour_unit(unit) {
        Ok(h)
    } else {
        Err("invalid rolling hours".into())
    }
}

fn is_hour_unit(u: &str) -> bool {
    matches!(u, "h" | "hr" | "hrs" | "hour" | "hours")
}

fn is_minute_unit(u: &str) -> bool {
    matches!(u, "m" | "min" | "mins" | "minute" | "minutes")
}

/// Simplified UI status chip state for a game with playtime limits.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum PlaytimeChipState {
    #[default]
    Playing,
    FinishingMatch,
    Overtime,
}

/// Live runtime playtime status returned in [`crate::ipc::ServiceSnapshot`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlaytimeRuleStatus {
    pub rule_id: Uuid,
    pub chip_state: PlaytimeChipState,
    /// `true` if global playtime limits AND this rule's playtime limit are enabled.
    pub limits_active: bool,
    pub is_exempt_today: bool,
    pub daily_budget_secs: u64,
    pub remaining_today_secs: u64,
    pub used_today_secs: u64,
    pub overtime_debt_secs: u64,
    /// `true` when Curb has a first-class per-title match detector for this Steam AppID.
    pub first_class: bool,
    #[serde(default)]
    pub detector_name: Option<String>,
    #[serde(default)]
    pub live_telemetry: Option<String>,
}

/// 1-minute usage bucket for rolling-hour interval caps.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UsageBucket {
    pub minute_epoch: i64,
    pub secs: u32,
}

/// Persisted playtime tracking record for a single rule.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleUsageRecord {
    pub day_key: String,
    pub week_key: String,
    pub used_today_secs: u64,
    pub used_week_secs: u64,
    #[serde(default)]
    pub rolling_buckets: Vec<UsageBucket>,
    /// Overtime debt carried in from previous interval(s), deducted from today's budget.
    #[serde(default)]
    pub overtime_debt_secs: u64,
    /// Overtime accumulated during today's `FinishingMatch` grace period (rolls into tomorrow's debt).
    #[serde(default)]
    pub active_overtime_secs: u64,
    #[serde(default)]
    pub draining_match: bool,
    #[serde(default)]
    pub expired_today: bool,
}

/// Persistent playtime ledger stored in `usage.json` inside Curb's admin-only data dir.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UsageLedger {
    pub version: u32,
    #[serde(default)]
    pub rules: HashMap<Uuid, RuleUsageRecord>,
}

impl Default for UsageLedger {
    fn default() -> Self {
        Self {
            version: 1,
            rules: HashMap::new(),
        }
    }
}

fn day_key(now: DateTime<Local>) -> String {
    now.format("%Y-%m-%d").to_string()
}

fn week_key(now: DateTime<Local>) -> String {
    let iso = now.iso_week();
    format!("{:04}-W{:02}", iso.year(), iso.week())
}

impl UsageLedger {
    /// Rolls daily/weekly counters when the local calendar day or ISO week changes,
    /// carrying over any `active_overtime_secs` into `overtime_debt_secs` when enabled.
    pub fn roll_windows_if_needed(
        &mut self,
        rule_id: Uuid,
        carry_over_debt: bool,
        now: DateTime<Local>,
    ) -> &mut RuleUsageRecord {
        let today = day_key(now);
        let this_week = week_key(now);
        let rec = self.rules.entry(rule_id).or_default();

        if rec.day_key.is_empty() {
            rec.day_key = today;
            rec.week_key = this_week;
            return rec;
        }

        if rec.day_key != today {
            if carry_over_debt && rec.active_overtime_secs > 0 {
                rec.overtime_debt_secs = rec
                    .overtime_debt_secs
                    .saturating_add(rec.active_overtime_secs);
            } else if !carry_over_debt {
                rec.overtime_debt_secs = 0;
            }
            rec.day_key = today;
            rec.used_today_secs = 0;
            rec.active_overtime_secs = 0;
            rec.draining_match = false;
            rec.expired_today = false;
        }

        if rec.week_key != this_week {
            rec.week_key = this_week;
            rec.used_week_secs = 0;
        }

        // Prune rolling buckets older than 7 days.
        let cutoff_min = (now.timestamp() / 60) - (7 * 24 * 60);
        rec.rolling_buckets.retain(|b| b.minute_epoch >= cutoff_min);

        rec
    }

    /// Computes `(remaining_today_secs, effective_daily_budget_secs, is_exempt_today)` for a rule.
    pub fn remaining_today(
        &mut self,
        rule_id: Uuid,
        limit: &PlaytimeLimitConfig,
        now: DateTime<Local>,
    ) -> (u64, u64, bool) {
        let policy = limit.budget.effective_policy();
        let weekday = now.weekday().num_days_from_sunday() as u8;
        let rec = self.roll_windows_if_needed(rule_id, limit.carry_over_debt, now);

        // Determine nominal daily ceiling for progress bar denominator.
        let mut nominal_daily_secs = u64::MAX;
        for cap in &policy.caps {
            let cap_secs = (cap.minutes as u64) * 60;
            match cap.window {
                CapWindow::Daily | CapWindow::RollingHours { .. } => {
                    nominal_daily_secs = nominal_daily_secs.min(cap_secs);
                }
                CapWindow::Weekly => {
                    if nominal_daily_secs == u64::MAX {
                        nominal_daily_secs = cap_secs;
                    }
                }
            }
        }
        if nominal_daily_secs == u64::MAX {
            nominal_daily_secs = 2 * 3600;
        }

        if policy.exempt_weekdays.contains(&weekday) {
            return (nominal_daily_secs, nominal_daily_secs, true);
        }

        let debt = if limit.carry_over_debt {
            rec.overtime_debt_secs
        } else {
            0
        };

        let mut min_remaining = u64::MAX;
        let now_min = now.timestamp() / 60;
        for cap in &policy.caps {
            let cap_secs = (cap.minutes as u64) * 60;
            let rem = match cap.window {
                CapWindow::Daily => cap_secs.saturating_sub(rec.used_today_secs.saturating_add(debt)),
                CapWindow::Weekly => cap_secs.saturating_sub(rec.used_week_secs.saturating_add(debt)),
                CapWindow::RollingHours { hours } => {
                    let window_start = now_min - (hours as i64 * 60);
                    let used_in_window: u64 = rec
                        .rolling_buckets
                        .iter()
                        .filter(|b| b.minute_epoch >= window_start)
                        .map(|b| b.secs as u64)
                        .sum();
                    cap_secs.saturating_sub(used_in_window.saturating_add(debt))
                }
            };
            min_remaining = min_remaining.min(rem);
        }

        if min_remaining == u64::MAX {
            min_remaining = nominal_daily_secs;
        }

        (min_remaining, nominal_daily_secs, false)
    }

    /// Advances usage by `delta_secs` while the game is running and returns the updated [`PlaytimeChipState`].
    pub fn record_tick(
        &mut self,
        rule_id: Uuid,
        limit: &PlaytimeLimitConfig,
        delta_secs: u64,
        in_match: bool,
        has_first_class_detector: bool,
        now: DateTime<Local>,
    ) -> PlaytimeChipState {
        let (remaining_before, _, exempt) = self.remaining_today(rule_id, limit, now);
        if exempt {
            let rec = self.rules.entry(rule_id).or_default();
            rec.draining_match = false;
            rec.expired_today = false;
            return PlaytimeChipState::Playing;
        }

        let max_overtime_secs = (limit.max_overtime_minutes as u64) * 60;
        let rec = self.rules.entry(rule_id).or_default();

        if rec.expired_today {
            return PlaytimeChipState::Overtime;
        }

        // Accumulate usage into today, week, and rolling minute buckets.
        if delta_secs > 0 {
            rec.used_today_secs = rec.used_today_secs.saturating_add(delta_secs);
            rec.used_week_secs = rec.used_week_secs.saturating_add(delta_secs);
            let minute_epoch = now.timestamp() / 60;
            if let Some(last) = rec.rolling_buckets.last_mut() {
                if last.minute_epoch == minute_epoch {
                    last.secs = last.secs.saturating_add(delta_secs as u32);
                } else {
                    rec.rolling_buckets.push(UsageBucket {
                        minute_epoch,
                        secs: delta_secs as u32,
                    });
                }
            } else {
                rec.rolling_buckets.push(UsageBucket {
                    minute_epoch,
                    secs: delta_secs as u32,
                });
            }
        }

        let remaining_after = remaining_before.saturating_sub(delta_secs);
        if remaining_after > 0 {
            rec.draining_match = false;
            return PlaytimeChipState::Playing;
        }

        // Budget exhausted. Check if we should wait for an active match to finish.
        if limit.wait_for_match_end && has_first_class_detector && in_match {
            let overtime_delta = delta_secs.saturating_sub(remaining_before);
            rec.active_overtime_secs = rec.active_overtime_secs.saturating_add(overtime_delta);
            if rec.active_overtime_secs >= max_overtime_secs && max_overtime_secs > 0 {
                rec.draining_match = false;
                rec.expired_today = true;
                return PlaytimeChipState::Overtime;
            }
            rec.draining_match = true;
            return PlaytimeChipState::FinishingMatch;
        }

        // Not in match (or no match-aware detector / disabled) -> cut immediately.
        rec.draining_match = false;
        rec.expired_today = true;
        PlaytimeChipState::Overtime
    }

    /// Called when a limited game process exits cleanly. If it was draining a match,
    /// mark it expired so relaunching stays cut until reset.
    pub fn on_game_exit(&mut self, rule_id: Uuid) {
        if let Some(rec) = self.rules.get_mut(&rule_id) {
            if rec.draining_match {
                rec.draining_match = false;
                rec.expired_today = true;
            }
        }
    }

    /// Resets today's usage and carried overtime debt for a single rule (admin action).
    pub fn reset_rule(&mut self, rule_id: Uuid, now: DateTime<Local>) {
        let rec = self.rules.entry(rule_id).or_default();
        rec.day_key = day_key(now);
        rec.week_key = week_key(now);
        rec.used_today_secs = 0;
        rec.used_week_secs = 0;
        rec.rolling_buckets.clear();
        rec.overtime_debt_secs = 0;
        rec.active_overtime_secs = 0;
        rec.draining_match = false;
        rec.expired_today = false;
    }

    /// Resets usage and debt across all rules (admin action).
    pub fn reset_all(&mut self, now: DateTime<Local>) {
        let ids: Vec<Uuid> = self.rules.keys().copied().collect();
        for id in ids {
            self.reset_rule(id, now);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn parses_custom_and_rules_with_exempt_days() {
        let parsed = parse_custom_budget("5h per day, 10h per week, except sunday").unwrap();
        assert_eq!(parsed.caps.len(), 2);
        assert_eq!(
            parsed.caps[0],
            IntervalCap {
                minutes: 300,
                window: CapWindow::Daily
            }
        );
        assert_eq!(
            parsed.caps[1],
            IntervalCap {
                minutes: 600,
                window: CapWindow::Weekly
            }
        );
        assert_eq!(parsed.exempt_weekdays, vec![0]);

        let multi = parse_custom_budget("1.5h/day and 45m per 4h, except sat, sun").unwrap();
        assert_eq!(multi.caps[0].minutes, 90);
        assert_eq!(
            multi.caps[1],
            IntervalCap {
                minutes: 45,
                window: CapWindow::RollingHours { hours: 4 }
            }
        );
        assert_eq!(multi.exempt_weekdays, vec![0, 6]);
    }

    #[test]
    fn waits_for_match_end_and_carries_overtime_debt_to_next_day() {
        let mut ledger = UsageLedger::default();
        let rule_id = Uuid::new_v4();
        let limit = PlaytimeLimitConfig {
            enabled: true,
            budget: PlaytimeBudget::Daily { hours: 1.0 },
            wait_for_match_end: true,
            max_overtime_minutes: 30,
            carry_over_debt: true,
        };

        // Monday 18:00 local
        let day1 = Local.with_ymd_and_hms(2026, 11, 23, 18, 0, 0).unwrap();
        // Play 55 min -> still Playing
        assert_eq!(
            ledger.record_tick(rule_id, &limit, 55 * 60, true, true, day1),
            PlaytimeChipState::Playing
        );
        // Play another 10 min while in match -> 5 min overtime, FinishingMatch
        assert_eq!(
            ledger.record_tick(rule_id, &limit, 10 * 60, true, true, day1),
            PlaytimeChipState::FinishingMatch
        );
        // Match ends -> transitions to Overtime (internet cut)
        assert_eq!(
            ledger.record_tick(rule_id, &limit, 2, false, true, day1),
            PlaytimeChipState::Overtime
        );

        // Next day (Tuesday): 5m overtime debt is deducted from 60m budget -> 55m remaining
        let day2 = Local.with_ymd_and_hms(2026, 11, 24, 10, 0, 0).unwrap();
        let (rem, daily, exempt) = ledger.remaining_today(rule_id, &limit, day2);
        assert!(!exempt);
        assert_eq!(daily, 3600);
        assert_eq!(rem, 55 * 60);

        // Admin reset restores full 60m
        ledger.reset_rule(rule_id, day2);
        let (rem_after, _, _) = ledger.remaining_today(rule_id, &limit, day2);
        assert_eq!(rem_after, 3600);
    }

    #[test]
    fn honors_exempt_weekday_sunday() {
        let mut ledger = UsageLedger::default();
        let rule_id = Uuid::new_v4();
        let expr = "1h per day, except sunday".to_string();
        let parsed = parse_custom_budget(&expr).unwrap();
        let limit = PlaytimeLimitConfig {
            enabled: true,
            budget: PlaytimeBudget::Custom {
                expression: expr,
                parsed,
            },
            wait_for_match_end: true,
            max_overtime_minutes: 30,
            carry_over_debt: true,
        };

        // Sunday 2026-11-22
        let sunday = Local.with_ymd_and_hms(2026, 11, 22, 15, 0, 0).unwrap();
        let (_, _, exempt) = ledger.remaining_today(rule_id, &limit, sunday);
        assert!(exempt);
        assert_eq!(
            ledger.record_tick(rule_id, &limit, 7200, false, true, sunday),
            PlaytimeChipState::Playing
        );
    }
}
