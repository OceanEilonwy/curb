use std::collections::HashSet;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use chrono::Local;
use curb_core::config::ExecutableMatcher;
use curb_core::playtime::{PlaytimeChipState, PlaytimeRuleStatus};
use curb_core::store::save_usage;
use curb_games::telemetry::TelemetrySampler;
use curb_games::{resolve_watched_dirs, DetectorRegistry, MatchState};
use tracing::{info, warn};
use uuid::Uuid;

use crate::engine::{LockExt, ServiceEngine};

/// Background 2-second loop that tracks active Steam game playtime, runs per-title
/// match-state detectors, persists `usage.json`, and notifies firewall reconciliation
/// whenever a game enters or exits `Overtime` (internet cut).
pub async fn run_playtime_loop(
    engine: ServiceEngine,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut registry = DetectorRegistry::default();
    let mut sampler = TelemetrySampler::new();
    let mut running_rules: HashSet<Uuid> = HashSet::new();
    let mut last_tick = Instant::now();
    let mut last_persist = Instant::now();
    let mut tick = tokio::time::interval(Duration::from_secs(2));

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    let guard = engine.state.lock_or_recover();
                    let _ = save_usage(&guard.data_dir, &guard.usage_ledger);
                    break;
                }
            }
            _ = tick.tick() => {}
        }

        let now_instant = Instant::now();
        let delta_secs = now_instant.duration_since(last_tick).as_secs().clamp(1, 10);
        last_tick = now_instant;
        let now_local = Local::now();

        // Snapshot rule definitions needed for sampling without holding the state lock.
        let (steam_root, global_enabled, rule_infos) = {
            let guard = engine.state.lock_or_recover();
            let root =
                curb_preset_steam::SteamPresetPlugin::find_steam_root(guard.preset_host.as_ref());
            let infos: Vec<_> = guard
                .config
                .rules
                .iter()
                .map(|r| {
                    let (app_id, install_dir) = match &r.matcher {
                        ExecutableMatcher::SteamGame {
                            app_id,
                            install_dir,
                            ..
                        } => (Some(*app_id), Some(PathBuf::from(install_dir))),
                        _ => (None, None),
                    };
                    (
                        r.id,
                        r.name.clone(),
                        r.enabled,
                        r.exe_hint.clone(),
                        app_id,
                        install_dir,
                        r.playtime_limit.clone(),
                    )
                })
                .collect();
            (root, guard.config.playtime_limits_enabled, infos)
        };

        let mut any_running_limited = false;
        let mut trigger_reconcile = false;
        let mut persist_now = false;

        for (rule_id, rule_name, rule_enabled, exe_hint, app_id_opt, install_dir, limit_opt) in
            rule_infos
        {
            let first_class_info = app_id_opt.and_then(|id| registry.info(id));
            let first_class = first_class_info.is_some();
            let detector_name = first_class_info.as_ref().map(|i| i.plugin_name.to_string());

            let Some(limit) = limit_opt else {
                // Still expose first_class metadata for Steam games so the UI badge renders.
                if first_class {
                    let mut guard = engine.state.lock_or_recover();
                    guard.playtime_statuses.insert(
                        rule_id,
                        PlaytimeRuleStatus {
                            rule_id,
                            chip_state: PlaytimeChipState::Playing,
                            limits_active: false,
                            is_exempt_today: false,
                            daily_budget_secs: 0,
                            remaining_today_secs: 0,
                            used_today_secs: 0,
                            overtime_debt_secs: 0,
                            first_class,
                            detector_name,
                            live_telemetry: None,
                        },
                    );
                }
                continue;
            };

            let limits_active = rule_enabled && global_enabled && limit.enabled;
            let mut exe_hints: Vec<&str> = Vec::new();
            if !exe_hint.is_empty() {
                exe_hints.push(exe_hint.as_str());
            }
            if let Some(info) = &first_class_info {
                exe_hints.extend_from_slice(info.exe_hints);
            }

            let watched_dirs = if let Some(app_id) = app_id_opt {
                let rel = registry
                    .get_mut(app_id)
                    .map(|d| d.watched_relative_paths())
                    .unwrap_or(&[]);
                resolve_watched_dirs(app_id, steam_root.as_deref(), rel)
            } else {
                Vec::new()
            };

            let snap = sampler.sample(
                app_id_opt.unwrap_or(0),
                install_dir.as_deref(),
                &exe_hints,
                &watched_dirs,
            );
            let is_running = !snap.pids.is_empty();

            let (in_match, live_telemetry) = if is_running {
                if let Some(app_id) = app_id_opt {
                    if let Some(detector) = registry.get_mut(app_id) {
                        let det = detector.detect(&snap);
                        (det.state == MatchState::InMatch, Some(det.reason))
                    } else {
                        (false, Some("Timer-only (no match plugin)".into()))
                    }
                } else {
                    (false, None)
                }
            } else {
                if running_rules.remove(&rule_id) {
                    if let Some(app_id) = app_id_opt {
                        if let Some(detector) = registry.get_mut(app_id) {
                            detector.reset();
                        }
                    }
                    let mut guard = engine.state.lock_or_recover();
                    guard.usage_ledger.on_game_exit(rule_id);
                    persist_now = true;
                }
                (false, None)
            };

            if is_running {
                running_rules.insert(rule_id);
            }

            let mut guard = engine.state.lock_or_recover();
            let prev_expired = guard
                .playtime_statuses
                .get(&rule_id)
                .is_some_and(|s| s.limits_active && s.chip_state == PlaytimeChipState::Overtime);

            let chip_state = if !limits_active {
                let _ = guard
                    .usage_ledger
                    .remaining_today(rule_id, &limit, now_local);
                PlaytimeChipState::Playing
            } else if is_running {
                any_running_limited = true;
                guard.usage_ledger.record_tick(
                    rule_id,
                    &limit,
                    delta_secs,
                    in_match,
                    first_class,
                    now_local,
                )
            } else {
                let (rem, _, exempt) =
                    guard
                        .usage_ledger
                        .remaining_today(rule_id, &limit, now_local);
                let rec = guard.usage_ledger.rules.get(&rule_id);
                if !exempt && (rem == 0 || rec.is_some_and(|r| r.expired_today)) {
                    PlaytimeChipState::Overtime
                } else {
                    PlaytimeChipState::Playing
                }
            };

            let (remaining_today_secs, daily_budget_secs, is_exempt_today) =
                guard
                    .usage_ledger
                    .remaining_today(rule_id, &limit, now_local);
            let (used_today_secs, overtime_debt_secs) = guard
                .usage_ledger
                .rules
                .get(&rule_id)
                .map(|r| {
                    (
                        r.used_today_secs,
                        r.overtime_debt_secs.saturating_add(r.active_overtime_secs),
                    )
                })
                .unwrap_or((0, 0));

            let now_expired = limits_active && chip_state == PlaytimeChipState::Overtime;
            if prev_expired != now_expired {
                guard.config_version = guard.config_version.wrapping_add(1);
                trigger_reconcile = true;
                persist_now = true;
                if now_expired {
                    info!(
                        "Playtime limit reached for '{}' — cutting internet access (Overtime)",
                        rule_name
                    );
                } else {
                    info!(
                        "Playtime limit restored for '{}' — allowing internet access",
                        rule_name
                    );
                }
            }

            guard.playtime_statuses.insert(
                rule_id,
                PlaytimeRuleStatus {
                    rule_id,
                    chip_state,
                    limits_active,
                    is_exempt_today,
                    daily_budget_secs,
                    remaining_today_secs,
                    used_today_secs,
                    overtime_debt_secs,
                    first_class,
                    detector_name,
                    live_telemetry,
                },
            );
        }

        if persist_now || (any_running_limited && last_persist.elapsed() >= Duration::from_secs(30))
        {
            let guard = engine.state.lock_or_recover();
            if let Err(e) = save_usage(&guard.data_dir, &guard.usage_ledger) {
                warn!("Failed to persist usage.json: {e}");
            }
            last_persist = Instant::now();
        }

        if trigger_reconcile {
            engine.notify_reconcile();
        }
    }
}
