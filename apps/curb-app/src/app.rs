use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};
use curb_core::config::{
    BaselinePolicy, EnforcementMode, ExecutableMatcher, NetworkPolicy, Rule, SubprocessPolicy,
    VerificationMethod,
};
use curb_core::ipc::{ProtectionTier, RunningAppInfo, ServiceSnapshot};
use curb_core::presets::SteamPresetConfig;
use curb_core::steam::DiscoveredSteamGame;
use curb_core::verify::BinaryIdentity;
use slint::{Color, ComponentHandle, ModelRc, SharedString, Timer, TimerMode, VecModel, Weak};
use uuid::Uuid;

use crate::backend::CurbBackend;
use crate::window_placement::{capture_geometry, SavedWindowGeometry};

slint::include_modules!();

const AVATAR_COLORS: [(u8, u8, u8); 8] = [
    (0x5c, 0x42, 0xcc),
    (0x47, 0x52, 0xc4),
    (0x18, 0x7e, 0x45),
    (0x03, 0x69, 0xa1),
    (0xbe, 0x12, 0x3c),
    (0xb4, 0x53, 0x09),
    (0x0e, 0x74, 0x90),
    (0x47, 0x55, 0x69),
];

pub fn avatar_color_for(name: &str) -> Color {
    let mut hash: u32 = 0;
    for ch in name.encode_utf16() {
        hash = hash.wrapping_mul(31).wrapping_add(ch as u32);
    }
    let (r, g, b) = AVATAR_COLORS[(hash as usize) % AVATAR_COLORS.len()];
    Color::from_rgb_u8(r, g, b)
}

pub fn initials_for(name: &str) -> String {
    let parts: Vec<&str> = name.split_whitespace().collect();
    if parts.len() >= 2 {
        let a = parts[0].chars().next().unwrap_or_default();
        let b = parts[1].chars().next().unwrap_or_default();
        format!("{a}{b}").to_uppercase()
    } else {
        name.chars().take(2).collect::<String>().to_uppercase()
    }
}

pub fn format_relative_time(ts: chrono::DateTime<Utc>) -> String {
    let diff = Utc::now().signed_duration_since(ts).num_seconds().max(0);
    if diff < 45 {
        "Just now".into()
    } else if diff < 3600 {
        format!("{}m ago", diff / 60)
    } else {
        format!("{}h ago", diff / 3600)
    }
}

pub fn matcher_detail(matcher: &ExecutableMatcher) -> String {
    match matcher {
        ExecutableMatcher::Signature { subject_cn, .. } => format!("Signer: {subject_cn}"),
        ExecutableMatcher::Hash { sha256, .. } => {
            let short: String = sha256.chars().take(12).collect();
            format!("SHA-256: {short}…")
        }
        ExecutableMatcher::Path { path, .. } => format!("Path: {path}"),
        ExecutableMatcher::SteamGame { verification, .. } => match verification {
            VerificationMethod::Signature { subject_cn, .. } => format!("Signer: {subject_cn}"),
            VerificationMethod::Hash { sha256, .. } => {
                let short: String = sha256.chars().take(12).collect();
                format!("SHA-256: {short}…")
            }
        },
    }
}

pub fn subprocess_to_int(p: SubprocessPolicy) -> i32 {
    match p {
        SubprocessPolicy::Disabled => 0,
        SubprocessPolicy::SameSignerOrDir => 1,
        SubprocessPolicy::AnyExceptRestricted => 2,
    }
}

pub fn int_to_subprocess(v: i32) -> SubprocessPolicy {
    match v {
        0 => SubprocessPolicy::Disabled,
        2 => SubprocessPolicy::AnyExceptRestricted,
        _ => SubprocessPolicy::SameSignerOrDir,
    }
}

pub fn steam_summary(steam: &SteamPresetConfig) -> String {
    if !steam.enabled {
        return "Blocked".into();
    }
    let mut parts = vec!["Downloads"];
    if steam.store_and_library {
        parts.push("Store");
    }
    if steam.community_and_workshop {
        parts.push("Community");
    }
    if steam.friends_and_voice {
        parts.push("Friends");
    }
    parts.join(" · ")
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum PromptPurpose {
    None,
    AddDomain(Uuid),
    BrowseExe,
}

#[derive(Clone)]
struct SelectedSummary {
    is_steam: bool,
    name: String,
    exe: String,
    path: String,
    signed: bool,
    signer: Option<String>,
    sha256: String,
    app_id: Option<u32>,
    install_dir: Option<String>,
}

struct AppController {
    gen_id: u64,
    backend: CurbBackend,
    win: Weak<MainWindow>,
    on_window_dropped: Rc<dyn Fn()>,
    theme_dark_pref: Rc<Cell<bool>>,
    last_geometry: Rc<RefCell<Option<SavedWindowGeometry>>>,

    snapshot: Option<ServiceSnapshot>,
    token: Option<String>,
    pending_open_allow: bool,

    expanded_id: Option<String>,
    adv_open: HashSet<String>,

    locking: bool,
    hiding_to_tray: bool,
    busy_steam: bool,
    busy_baseline: bool,
    pending_mode: Option<i32>,
    busy_rules: HashSet<Uuid>,
    deleting_rule: Option<Uuid>,
    allowing_blocked: Option<Uuid>,

    // Picker state
    running_apps: Vec<RunningAppInfo>,
    steam_games: Vec<DiscoveredSteamGame>,
    loading_running: bool,
    loading_steam: bool,
    running_req_id: u64,
    steam_req_id: u64,
    search: String,
    show_bg: bool,
    selected_key: Option<String>,
    browsed: Option<RunningAppInfo>,
    inspected_by_path: HashMap<String, RunningAppInfo>,
    inspecting_path: Option<String>,
    inspect_req_id: u64,
    inspect_error: Option<String>,
    saving_rule: bool,

    prompt_purpose: PromptPurpose,
    toast_timer: Timer,
    poll_timer: Timer,
}

thread_local! {
    static NEXT_GEN: Cell<u64> = const { Cell::new(1) };
    static ACTIVE_CONTROLLER: RefCell<Option<(u64, Rc<RefCell<AppController>>)>> = const { RefCell::new(None) };
}

fn with_controller<F: FnOnce(&mut AppController)>(gen_id: u64, f: F) {
    let rc = ACTIVE_CONTROLLER.with(|cell| {
        let borrow = cell.borrow();
        match borrow.as_ref() {
            Some((id, rc)) if *id == gen_id => Some(rc.clone()),
            _ => None,
        }
    });
    if let Some(rc) = rc {
        let mut guard = rc.borrow_mut();
        f(&mut guard);
    }
}

pub fn clear_active_controller(gen_id: u64) {
    ACTIVE_CONTROLLER.with(|cell| {
        let mut borrow = cell.borrow_mut();
        if matches!(borrow.as_ref(), Some((id, _)) if *id == gen_id) {
            *borrow = None;
        }
    });
}

/// Instantiates a fresh `MainWindow`, wires all callbacks to `CurbBackend`,
/// applies the persisted theme preference, and starts loading the initial snapshot.
pub fn create_main_window(
    backend: CurbBackend,
    theme_dark_pref: Rc<Cell<bool>>,
    last_geometry: Rc<RefCell<Option<SavedWindowGeometry>>>,
    on_window_dropped: Rc<dyn Fn()>,
) -> Result<(u64, MainWindow), slint::PlatformError> {
    let win = MainWindow::new()?;
    win.global::<Theme>().set_is_dark(theme_dark_pref.get());

    let gen_id = NEXT_GEN.with(|c| {
        let id = c.get();
        c.set(id + 1);
        id
    });

    let ctrl = Rc::new(RefCell::new(AppController {
        gen_id,
        backend,
        win: win.as_weak(),
        on_window_dropped,
        theme_dark_pref,
        last_geometry,
        snapshot: None,
        token: None,
        pending_open_allow: false,
        expanded_id: Some("steam".into()),
        adv_open: HashSet::new(),
        locking: false,
        hiding_to_tray: false,
        busy_steam: false,
        busy_baseline: false,
        pending_mode: None,
        busy_rules: HashSet::new(),
        deleting_rule: None,
        allowing_blocked: None,
        running_apps: Vec::new(),
        steam_games: Vec::new(),
        loading_running: false,
        loading_steam: false,
        running_req_id: 0,
        steam_req_id: 0,
        search: String::new(),
        show_bg: false,
        selected_key: None,
        browsed: None,
        inspected_by_path: HashMap::new(),
        inspecting_path: None,
        inspect_req_id: 0,
        inspect_error: None,
        saving_rule: false,
        prompt_purpose: PromptPurpose::None,
        toast_timer: Timer::default(),
        poll_timer: Timer::default(),
    }));

    ACTIVE_CONTROLLER.with(|cell| {
        *cell.borrow_mut() = Some((gen_id, ctrl.clone()));
    });

    wire_callbacks(&win, gen_id);

    // Handle OS window close (Alt+F4 / taskbar close) identically to close-to-tray
    win.window().on_close_requested(move || {
        with_controller(gen_id, |c| c.handle_close_to_tray());
        slint::CloseRequestResponse::KeepWindowShown
    });

    // Kick off initial snapshot fetch + 3s silent background polling while window is open
    {
        let mut c = ctrl.borrow_mut();
        c.refresh_snapshot_opts(false);
        c.poll_timer
            .start(TimerMode::Repeated, Duration::from_secs(3), move || {
                with_controller(gen_id, |c| c.refresh_snapshot_opts(true));
            });
    }

    Ok((gen_id, win))
}

fn wire_callbacks(win: &MainWindow, gen_id: u64) {
    win.on_close_to_tray(move || with_controller(gen_id, |c| c.handle_close_to_tray()));
    win.on_toggle_lock_btn(move || with_controller(gen_id, |c| c.handle_toggle_lock_btn()));
    win.on_open_unlock(move || with_controller(gen_id, |c| c.open_unlock_modal()));
    win.on_close_unlock(move || with_controller(gen_id, |c| c.close_unlock_modal()));
    win.on_submit_unlock(move |pw, cf| {
        with_controller(gen_id, |c| c.handle_submit_unlock(pw.into(), cf.into()))
    });
    win.on_close_prompt(move || with_controller(gen_id, |c| c.close_prompt_modal()));
    win.on_submit_prompt(move |val| {
        with_controller(gen_id, |c| c.handle_submit_prompt(val.into()))
    });
    win.on_tab_selected(move |idx| with_controller(gen_id, |c| c.handle_tab_selected(idx)));
    win.on_open_allow_sheet(move || with_controller(gen_id, |c| c.open_allow_sheet()));

    // Setup
    win.on_setup_full(move || with_controller(gen_id, |c| c.handle_setup_full()));
    win.on_setup_standard(move |pw, cf| {
        with_controller(gen_id, |c| c.handle_setup_standard(pw.into(), cf.into()))
    });

    // Steam preset
    win.on_toggle_steam_expand(move || with_controller(gen_id, |c| c.toggle_expand("steam")));
    win.on_toggle_steam_adv(move || with_controller(gen_id, |c| c.toggle_adv("steam")));
    win.on_toggle_steam_enabled(move || {
        with_controller(gen_id, |c| c.mutate_steam(|s| s.enabled = !s.enabled))
    });
    win.on_toggle_steam_store(move || {
        with_controller(gen_id, |c| {
            c.mutate_steam(|s| s.store_and_library = !s.store_and_library)
        })
    });
    win.on_toggle_steam_community(move || {
        with_controller(gen_id, |c| {
            c.mutate_steam(|s| s.community_and_workshop = !s.community_and_workshop)
        })
    });
    win.on_toggle_steam_friends(move || {
        with_controller(gen_id, |c| {
            c.mutate_steam(|s| s.friends_and_voice = !s.friends_and_voice)
        })
    });

    // Rules
    win.on_toggle_rule_expand(move |id| with_controller(gen_id, |c| c.toggle_expand(&id)));
    win.on_toggle_rule_adv(move |id| with_controller(gen_id, |c| c.toggle_adv(&id)));
    win.on_toggle_rule_enabled(move |id| {
        with_controller(gen_id, |c| c.mutate_rule(&id, |r| r.enabled = !r.enabled))
    });
    win.on_toggle_rule_helpers(move |id| {
        with_controller(gen_id, |c| {
            c.mutate_rule(&id, |r| {
                r.subprocesses = if r.subprocesses == SubprocessPolicy::Disabled {
                    SubprocessPolicy::SameSignerOrDir
                } else {
                    SubprocessPolicy::Disabled
                };
            })
        })
    });
    win.on_toggle_rule_tcp(move |id| {
        with_controller(gen_id, |c| {
            c.mutate_rule(&id, |r| r.network.allow_tcp = !r.network.allow_tcp)
        })
    });
    win.on_toggle_rule_udp(move |id| {
        with_controller(gen_id, |c| {
            c.mutate_rule(&id, |r| r.network.allow_udp = !r.network.allow_udp)
        })
    });
    win.on_set_rule_subprocesses(move |id, val| {
        with_controller(gen_id, |c| {
            c.mutate_rule(&id, |r| r.subprocesses = int_to_subprocess(val))
        })
    });
    win.on_open_add_domain(move |id| with_controller(gen_id, |c| c.open_add_domain_prompt(&id)));
    win.on_remove_rule_domain(move |id, idx| {
        with_controller(gen_id, |c| c.handle_remove_domain(&id, idx))
    });
    win.on_delete_rule(move |id| with_controller(gen_id, |c| c.handle_delete_rule(&id)));

    // Blocked
    win.on_allow_blocked_event(move |id| {
        with_controller(gen_id, |c| c.handle_allow_blocked(&id))
    });

    // Settings
    win.on_upgrade_to_full(move || with_controller(gen_id, |c| c.handle_upgrade_to_full()));
    win.on_uninstall_service(move || with_controller(gen_id, |c| c.handle_uninstall_service()));
    win.on_toggle_theme(move || with_controller(gen_id, |c| c.handle_toggle_theme()));
    win.on_set_mode(move |m| with_controller(gen_id, |c| c.handle_set_mode(m)));
    win.on_toggle_baseline_dhcp(move || {
        with_controller(gen_id, |c| c.mutate_baseline(|b| b.dhcp = !b.dhcp))
    });
    win.on_toggle_baseline_loopback(move || {
        with_controller(gen_id, |c| c.mutate_baseline(|b| b.loopback = !b.loopback))
    });
    win.on_toggle_baseline_ntp(move || {
        with_controller(gen_id, |c| c.mutate_baseline(|b| b.ntp = !b.ntp))
    });
    win.on_toggle_baseline_ncsi(move || {
        with_controller(gen_id, |c| c.mutate_baseline(|b| b.ncsi = !b.ncsi))
    });
    win.on_toggle_pw_form(move || with_controller(gen_id, |c| c.handle_toggle_pw_form()));
    win.on_submit_password_change(move |cur, next, conf| {
        with_controller(gen_id, |c| {
            c.handle_change_password(cur.into(), next.into(), conf.into())
        })
    });

    // AllowAppSheet picker
    win.on_picker_cancel(move || with_controller(gen_id, |c| c.close_allow_sheet()));
    win.on_picker_refresh(move || with_controller(gen_id, |c| c.refresh_picker_sources()));
    win.on_picker_search_changed(move |q| {
        with_controller(gen_id, |c| {
            c.search = q.into();
            c.sync_picker();
        })
    });
    win.on_picker_toggle_bg(move || {
        with_controller(gen_id, |c| {
            c.show_bg = !c.show_bg;
            c.sync_picker();
        })
    });
    win.on_picker_select(move |key| with_controller(gen_id, |c| c.select_picker_entry(key.into())));
    win.on_picker_retry_inspect(move || with_controller(gen_id, |c| c.retry_inspect_selected()));
    win.on_picker_open_browse(move || with_controller(gen_id, |c| c.open_browse_prompt()));
    win.on_picker_confirm(move || with_controller(gen_id, |c| c.handle_confirm_allow()));
}

impl AppController {
    fn window(&self) -> Option<MainWindow> {
        self.win.upgrade()
    }

    fn show_toast(&mut self, msg: impl Into<String>) {
        let Some(win) = self.window() else { return };
        win.set_toast_message(SharedString::from(msg.into()));
        let win_weak = self.win.clone();
        self.toast_timer
            .start(TimerMode::SingleShot, Duration::from_millis(2400), move || {
                if let Some(w) = win_weak.upgrade() {
                    w.set_toast_message(SharedString::default());
                }
            });
    }

    fn require_token(&mut self) -> Option<String> {
        if let Some(t) = &self.token {
            Some(t.clone())
        } else {
            self.open_unlock_modal();
            None
        }
    }

    fn open_unlock_modal(&mut self) {
        let Some(win) = self.window() else { return };
        win.set_unlock_password(SharedString::default());
        win.set_unlock_confirm(SharedString::default());
        win.set_unlock_error(SharedString::default());
        win.set_unlock_busy(false);
        win.set_unlock_open(true);
        win.invoke_focus_unlock();
    }

    fn close_unlock_modal(&mut self) {
        self.pending_open_allow = false;
        if let Some(win) = self.window() {
            win.set_unlock_open(false);
            win.set_unlock_password(SharedString::default());
            win.set_unlock_confirm(SharedString::default());
            win.set_unlock_error(SharedString::default());
            win.set_unlock_busy(false);
        }
    }

    fn close_prompt_modal(&mut self) {
        self.prompt_purpose = PromptPurpose::None;
        if let Some(win) = self.window() {
            win.set_prompt_open(false);
            win.set_prompt_value(SharedString::default());
            win.set_prompt_error(SharedString::default());
            win.set_prompt_busy(false);
        }
    }

    fn sync_all(&self) {
        let Some(win) = self.window() else { return };

        win.set_unlocked(self.token.is_some());
        win.set_locking(self.locking);
        win.set_hiding_to_tray(self.hiding_to_tray);
        win.set_busy_steam(self.busy_steam);
        win.set_busy_baseline(self.busy_baseline);
        win.set_pending_mode(self.pending_mode.unwrap_or(-1));
        win.set_any_allowing_blocked(self.allowing_blocked.is_some());

        let Some(snap) = &self.snapshot else {
            win.set_screen(0);
            return;
        };

        win.set_password_configured(snap.password_configured);
        win.set_is_full_service(snap.protection_tier == ProtectionTier::FullService);
        let outdated = snap.protection_tier == ProtectionTier::FullService
            && crate::elevate::is_service_outdated(&snap.service_version);
        win.set_service_outdated(outdated);
        let reported = if snap.service_version.is_empty() {
            "legacy".to_string()
        } else {
            format!("v{}", snap.service_version)
        };
        win.set_service_version_label(
            format!("{reported} → v{}", env!("CARGO_PKG_VERSION")).into(),
        );

        if snap.protection_tier == ProtectionTier::Unconfigured {
            win.set_screen(1);
            return;
        } else if win.get_screen() < 2 {
            win.set_screen(2);
        }

        // Mode visual (treat expired PausedUntil as Enforcing)
        let is_standard = snap.protection_tier == ProtectionTier::StandardUser;
        let now = Utc::now();
        let (mode_kind, mode_label) = match snap.config.mode {
            EnforcementMode::Enforcing => (
                0,
                if is_standard {
                    "Standard mode"
                } else {
                    "Internet limited"
                },
            ),
            EnforcementMode::PausedUntil { until } if until > now => (1, "Paused (15 min)"),
            EnforcementMode::PausedUntil { .. } => (
                0,
                if is_standard {
                    "Standard mode"
                } else {
                    "Internet limited"
                },
            ),
            EnforcementMode::Disabled => (2, "Protection off"),
        };
        win.set_mode_kind(mode_kind);
        win.set_mode_label(mode_label.into());

        // Allowed count
        let enabled_rules = snap.config.rules.iter().filter(|r| r.enabled).count();
        let active_count = enabled_rules + usize::from(snap.config.presets.steam.enabled);
        win.set_active_allowed_count(active_count as i32);

        // Steam preset
        let steam = &snap.config.presets.steam;
        win.set_steam_enabled(steam.enabled);
        win.set_steam_store(steam.store_and_library);
        win.set_steam_community(steam.community_and_workshop);
        win.set_steam_friends(steam.friends_and_voice);
        win.set_steam_summary(steam_summary(steam).into());
        win.set_steam_expanded(self.expanded_id.as_deref() == Some("steam"));
        win.set_steam_adv_open(self.adv_open.contains("steam"));
        let steam_doms: Vec<SharedString> =
            curb_preset_steam::SteamPresetPlugin::webhelper_domains(&steam.to_preset_state())
                .into_iter()
                .map(SharedString::from)
                .collect();
        win.set_steam_domains(ModelRc::new(VecModel::from(steam_doms)));

        // Baseline
        win.set_baseline_dhcp(snap.config.baseline.dhcp);
        win.set_baseline_loopback(snap.config.baseline.loopback);
        win.set_baseline_ntp(snap.config.baseline.ntp);
        win.set_baseline_ncsi(snap.config.baseline.ncsi);

        // Rules model
        let rule_items: Vec<RuleItem> = snap
            .config
            .rules
            .iter()
            .map(|r| {
                let id_str = r.id.to_string();
                let dns_list: Vec<SharedString> = r
                    .network
                    .dns_whitelist
                    .as_deref()
                    .unwrap_or(&[])
                    .iter()
                    .cloned()
                    .map(SharedString::from)
                    .collect();
                let deleting = self.deleting_rule == Some(r.id);
                let busy = self.busy_rules.contains(&r.id) || deleting;
                RuleItem {
                    id: id_str.clone().into(),
                    name: r.name.clone().into(),
                    enabled: r.enabled,
                    signed: r.matcher.is_signed(),
                    is_steam_game: matches!(r.matcher, ExecutableMatcher::SteamGame { .. }),
                    allow_helpers: r.subprocesses != SubprocessPolicy::Disabled,
                    allow_tcp: r.network.allow_tcp,
                    allow_udp: r.network.allow_udp,
                    subprocess_policy: subprocess_to_int(r.subprocesses),
                    dns_whitelist: ModelRc::new(VecModel::from(dns_list)),
                    exe_hint: r.exe_hint.clone().into(),
                    matcher_detail: matcher_detail(&r.matcher).into(),
                    expanded: self.expanded_id.as_deref() == Some(id_str.as_str()),
                    adv_open: self.adv_open.contains(&id_str),
                    busy,
                    deleting,
                }
            })
            .collect();
        win.set_rules(ModelRc::new(VecModel::from(rule_items)));

        // Blocked events model
        let blocked_items: Vec<BlockedEventItem> = snap
            .blocked_events
            .iter()
            .map(|ev| BlockedEventItem {
                id: ev.id.to_string().into(),
                app_name: ev.app_name.clone().into(),
                relative_time: format_relative_time(ev.timestamp).into(),
                destination: ev.destination.clone().into(),
                is_steam_community: ev.is_steam_community,
                allowing: self.allowing_blocked == Some(ev.id),
            })
            .collect();
        win.set_blocked_events(ModelRc::new(VecModel::from(blocked_items)));

        self.sync_picker();
    }

    fn is_already_allowed(
        &self,
        exe: &str,
        path: Option<&str>,
        steam_app_id: Option<u32>,
    ) -> bool {
        let Some(snap) = &self.snapshot else {
            return false;
        };
        snap.config.rules.iter().any(|r| {
            if let Some(app_id) = steam_app_id {
                if matches!(r.matcher, ExecutableMatcher::SteamGame { app_id: id, .. } if id == app_id)
                {
                    return true;
                }
            }
            if let (Some(p), Some(rule_path)) = (path, r.exe_path.as_deref()) {
                return rule_path.eq_ignore_ascii_case(p);
            }
            if r.exe_path.is_none() {
                return r.exe_hint.eq_ignore_ascii_case(exe);
            }
            false
        })
    }

    fn to_running_item(&self, app: &RunningAppInfo) -> RunningAppItem {
        let already = self.is_already_allowed(&app.exe, Some(&app.path), None);
        let selected = !already && self.selected_key.as_deref() == Some(app.key.as_str());
        RunningAppItem {
            key: app.key.clone().into(),
            name: app.name.clone().into(),
            initials: initials_for(&app.name).into(),
            avatar_color: avatar_color_for(&app.name),
            exe: app.exe.clone().into(),
            path: app.path.clone().into(),
            process_count: app.process_count as i32,
            background: app.background,
            tried_connect: app.tried_connect,
            tried_host: app.tried_host.clone().unwrap_or_default().into(),
            signed: app.signed,
            already_allowed: already,
            selected,
        }
    }

    fn selected_summary(&self) -> Option<SelectedSummary> {
        let key = self.selected_key.as_deref()?;

        if let Some(b) = &self.browsed {
            if b.key == key {
                return Some(SelectedSummary {
                    is_steam: false,
                    name: b.name.clone(),
                    exe: b.exe.clone(),
                    path: b.path.clone(),
                    signed: b.signed,
                    signer: b.signer.clone(),
                    sha256: b.sha256.clone(),
                    app_id: None,
                    install_dir: None,
                });
            }
        }

        if let Some(run) = self.running_apps.iter().find(|a| a.key == key) {
            let norm = run.path.to_ascii_lowercase();
            let verified = self.inspected_by_path.get(&norm);
            let sha256 = verified
                .map(|v| v.sha256.clone())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| run.sha256.clone());
            return Some(SelectedSummary {
                is_steam: false,
                name: run.name.clone(),
                exe: run.exe.clone(),
                path: run.path.clone(),
                signed: verified.map(|v| v.signed).unwrap_or(run.signed),
                signer: verified
                    .map(|v| v.signer.clone())
                    .unwrap_or_else(|| run.signer.clone()),
                sha256,
                app_id: None,
                install_dir: None,
            });
        }

        if let Some(game) = self
            .steam_games
            .iter()
            .find(|g| format!("steam-{}", g.app_id) == key)
        {
            let exe_path = game.exe_path.to_string_lossy().into_owned();
            let norm = exe_path.to_ascii_lowercase();
            let verified = self.inspected_by_path.get(&norm);
            let sha256 = verified
                .map(|v| v.sha256.clone())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| game.sha256.clone());
            return Some(SelectedSummary {
                is_steam: true,
                name: game.name.clone(),
                exe: game.exe_name.clone(),
                path: exe_path,
                signed: verified.map(|v| v.signed).unwrap_or(game.signed),
                signer: verified
                    .map(|v| v.signer.clone())
                    .unwrap_or_else(|| game.signer.clone()),
                sha256,
                app_id: Some(game.app_id),
                install_dir: Some(game.install_dir.to_string_lossy().into_owned()),
            });
        }

        None
    }

    fn sync_picker(&self) {
        let Some(win) = self.window() else { return };
        let q = self.search.trim().to_ascii_lowercase();

        win.set_picker_show_bg(self.show_bg);
        win.set_picker_bg_count(self.running_apps.iter().filter(|a| a.background).count() as i32);
        win.set_picker_loading_running(self.loading_running);
        win.set_picker_loading_steam(self.loading_steam);
        win.set_picker_total_running(self.running_apps.len() as i32);
        win.set_picker_total_steam(self.steam_games.len() as i32);
        win.set_picker_saving(self.saving_rule);

        if let Some(b) = &self.browsed {
            win.set_picker_has_browsed(true);
            win.set_picker_browsed_app(self.to_running_item(b));
        } else {
            win.set_picker_has_browsed(false);
        }

        let mut filtered: Vec<&RunningAppInfo> = self
            .running_apps
            .iter()
            .filter(|a| self.show_bg || !a.background)
            .filter(|a| {
                q.is_empty()
                    || a.name.to_ascii_lowercase().contains(&q)
                    || a.exe.to_ascii_lowercase().contains(&q)
                    || a.signer
                        .as_deref()
                        .map(|s| s.to_ascii_lowercase().contains(&q))
                        .unwrap_or(false)
            })
            .collect();

        filtered.sort_by_key(|a| {
            let already = u8::from(self.is_already_allowed(&a.exe, Some(&a.path), None));
            let not_tried = u8::from(!a.tried_connect);
            (already, not_tried)
        });

        let mut tried = Vec::new();
        let mut other = Vec::new();
        for app in filtered {
            let item = self.to_running_item(app);
            if app.tried_connect && !item.already_allowed {
                tried.push(item);
            } else {
                other.push(item);
            }
        }
        win.set_picker_tried_apps(ModelRc::new(VecModel::from(tried)));
        win.set_picker_other_apps(ModelRc::new(VecModel::from(other)));

        let steam_items: Vec<SteamGameItem> = self
            .steam_games
            .iter()
            .filter(|g| {
                q.is_empty()
                    || g.name.to_ascii_lowercase().contains(&q)
                    || g.exe_name.to_ascii_lowercase().contains(&q)
            })
            .map(|g| {
                let key = format!("steam-{}", g.app_id);
                let exe_path_str = g.exe_path.to_string_lossy().into_owned();
                let already =
                    self.is_already_allowed(&g.exe_name, Some(&exe_path_str), Some(g.app_id));
                let selected = !already && self.selected_key.as_deref() == Some(key.as_str());
                SteamGameItem {
                    key: key.into(),
                    app_id: g.app_id as i32,
                    name: g.name.clone().into(),
                    initials: initials_for(&g.name).into(),
                    avatar_color: avatar_color_for(&g.name),
                    exe_name: g.exe_name.clone().into(),
                    exe_path: exe_path_str.into(),
                    signed: g.signed,
                    already_allowed: already,
                    selected,
                }
            })
            .collect();
        win.set_picker_steam_games(ModelRc::new(VecModel::from(steam_items)));

        if let Some(sel) = self.selected_summary() {
            let norm = sel.path.to_ascii_lowercase();
            let inspecting = self.inspecting_path.as_deref() == Some(norm.as_str());
            win.set_picker_has_selection(true);
            win.set_picker_selected_name(sel.name.into());
            win.set_picker_selected_path(sel.path.into());
            win.set_picker_selected_signed(sel.signed);
            win.set_picker_selected_signer(sel.signer.unwrap_or_default().into());
            win.set_picker_selected_verified(!sel.sha256.is_empty());
            win.set_picker_inspecting(inspecting);
            win.set_picker_inspect_error(self.inspect_error.clone().unwrap_or_default().into());
        } else {
            win.set_picker_has_selection(false);
            win.set_picker_inspecting(false);
            win.set_picker_inspect_error(SharedString::default());
        }
    }

    // ---------- Actions ----------

    fn refresh_snapshot(&mut self) {
        self.refresh_snapshot_opts(false);
    }

    fn refresh_snapshot_opts(&mut self, silent: bool) {
        let gen_id = self.gen_id;
        let backend = self.backend.clone();
        self.backend.spawn(async move {
            let res = backend.get_snapshot().await;
            let _ = slint::invoke_from_event_loop(move || {
                with_controller(gen_id, |c| match res {
                    Ok(snap) => {
                        c.snapshot = Some(snap);
                        c.sync_all();
                    }
                    Err(e) => {
                        if !silent {
                            c.show_toast(format!("Service error: {e}"));
                        }
                    }
                });
            });
        });
    }

    fn handle_tab_selected(&mut self, idx: i32) {
        if let Some(win) = self.window() {
            win.set_active_tab(idx);
        }
        // Refresh snapshot when switching to Blocked so recent events stay up to date
        if idx == 1 {
            self.refresh_snapshot();
        }
    }

    fn handle_toggle_theme(&mut self) {
        let next = !self.theme_dark_pref.get();
        self.theme_dark_pref.set(next);
        if let Some(win) = self.window() {
            win.global::<Theme>().set_is_dark(next);
        }
    }

    fn handle_toggle_lock_btn(&mut self) {
        if self.locking || self.hiding_to_tray {
            return;
        }
        if self.token.is_some() {
            self.handle_lock();
        } else {
            self.open_unlock_modal();
        }
    }

    fn handle_lock(&mut self) {
        if self.locking {
            return;
        }
        self.locking = true;
        self.sync_all();

        let token = self.token.clone();
        let gen_id = self.gen_id;
        let backend = self.backend.clone();
        self.backend.spawn(async move {
            let res = if let Some(t) = token {
                backend.lock(t).await
            } else {
                Ok(())
            };
            let _ = slint::invoke_from_event_loop(move || {
                with_controller(gen_id, |c| {
                    c.locking = false;
                    match res {
                        Ok(()) => {
                            c.token = None;
                            c.pending_open_allow = false;
                            if let Some(w) = c.window() {
                                if w.get_screen() == 3 {
                                    w.set_screen(2);
                                }
                                w.set_pw_open(false);
                            }
                            c.show_toast("Locked");
                        }
                        Err(e) => c.show_toast(e),
                    }
                    c.sync_all();
                });
            });
        });
    }

    fn handle_close_to_tray(&mut self) {
        if self.hiding_to_tray {
            return;
        }
        self.hiding_to_tray = true;
        let token = self.token.take();
        self.pending_open_allow = false;
        let backend = self.backend.clone();

        if let Some(t) = token {
            self.backend.spawn(async move {
                let _ = backend.lock(t).await;
            });
        }

        if let Some(w) = self.window() {
            if let Some(geo) = capture_geometry(&w) {
                *self.last_geometry.borrow_mut() = Some(geo);
            }
            let _ = w.hide();
        }

        let gen_id = self.gen_id;
        let on_drop = self.on_window_dropped.clone();
        // Defer dropping the MainWindow & controller to the next event loop turn
        // so we are never dropping a component while inside its own callback stack.
        Timer::single_shot(Duration::ZERO, move || {
            clear_active_controller(gen_id);
            (on_drop)();
        });
    }

    fn handle_submit_unlock(&mut self, password: String, confirm: String) {
        let Some(win) = self.window() else { return };
        if win.get_unlock_busy() {
            return;
        }
        let configured = self
            .snapshot
            .as_ref()
            .map(|s| s.password_configured)
            .unwrap_or(true);

        if !configured {
            if password.len() < 4 {
                win.set_unlock_error("Password must be at least 4 characters.".into());
                return;
            }
            if password != confirm {
                win.set_unlock_error("Passwords do not match.".into());
                return;
            }
        }

        win.set_unlock_error(SharedString::default());
        win.set_unlock_busy(true);

        let gen_id = self.gen_id;
        let backend = self.backend.clone();
        self.backend.spawn(async move {
            let res = backend.unlock(password).await;
            let _ = slint::invoke_from_event_loop(move || {
                with_controller(gen_id, |c| {
                    if let Some(w) = c.window() {
                        w.set_unlock_busy(false);
                    }
                    match res {
                        Ok(tok) => {
                            c.token = Some(tok);
                            let open_allow = c.pending_open_allow;
                            c.close_unlock_modal();
                            c.show_toast("Unlocked · auto-locks when closed");
                            c.refresh_snapshot();
                            if open_allow {
                                c.enter_allow_sheet();
                            } else {
                                c.sync_all();
                            }
                        }
                        Err(e) => {
                            if let Some(w) = c.window() {
                                w.set_unlock_error(e.into());
                            }
                        }
                    }
                });
            });
        });
    }

    fn handle_setup_full(&mut self) {
        let Some(win) = self.window() else { return };
        if win.get_setup_busy() {
            return;
        }
        win.set_setup_error(SharedString::default());
        win.set_setup_busy(true);

        let gen_id = self.gen_id;
        let backend = self.backend.clone();
        self.backend.spawn(async move {
            let res = backend.setup_full_protection().await;
            let _ = slint::invoke_from_event_loop(move || {
                with_controller(gen_id, |c| {
                    if let Some(w) = c.window() {
                        w.set_setup_busy(false);
                    }
                    match res {
                        Ok(snap) => {
                            let needs_pw = !snap.password_configured;
                            c.snapshot = Some(snap);
                            c.sync_all();
                            c.show_toast("Full Protection active");
                            if needs_pw {
                                c.open_unlock_modal();
                            }
                        }
                        Err(e) => {
                            if let Some(w) = c.window() {
                                w.set_setup_error(e.into());
                            }
                        }
                    }
                });
            });
        });
    }

    fn handle_setup_standard(&mut self, password: String, confirm: String) {
        let Some(win) = self.window() else { return };
        if win.get_setup_busy() {
            return;
        }
        if password.len() < 4 {
            win.set_setup_error("Choose a password with at least 4 characters.".into());
            return;
        }
        if password != confirm {
            win.set_setup_error("Passwords do not match.".into());
            return;
        }

        win.set_setup_error(SharedString::default());
        win.set_setup_busy(true);

        let gen_id = self.gen_id;
        let backend = self.backend.clone();
        self.backend.spawn(async move {
            let res = backend.setup_standard_mode(password).await;
            let _ = slint::invoke_from_event_loop(move || {
                with_controller(gen_id, |c| {
                    if let Some(w) = c.window() {
                        w.set_setup_busy(false);
                    }
                    match res {
                        Ok((tok, snap)) => {
                            c.token = Some(tok);
                            c.snapshot = Some(snap);
                            c.sync_all();
                            c.show_toast("Standard Mode active");
                        }
                        Err(e) => {
                            if let Some(w) = c.window() {
                                w.set_setup_error(e.into());
                            }
                        }
                    }
                });
            });
        });
    }

    fn toggle_expand(&mut self, id: &str) {
        if self.expanded_id.as_deref() == Some(id) {
            self.expanded_id = None;
        } else {
            self.expanded_id = Some(id.to_string());
        }
        self.sync_all();
    }

    fn toggle_adv(&mut self, id: &str) {
        if self.adv_open.contains(id) {
            self.adv_open.remove(id);
        } else {
            self.adv_open.insert(id.to_string());
        }
        self.sync_all();
    }

    fn mutate_steam<F: FnOnce(&mut SteamPresetConfig)>(&mut self, f: F) {
        let Some(tok) = self.require_token() else {
            return;
        };
        if self.busy_steam {
            return;
        }
        let Some(mut steam) = self.snapshot.as_ref().map(|s| s.config.presets.steam.clone()) else {
            return;
        };
        f(&mut steam);
        self.update_steam_preset(tok, steam, None);
    }

    fn update_steam_preset(
        &mut self,
        tok: String,
        steam: SteamPresetConfig,
        success_toast: Option<&'static str>,
    ) {
        self.busy_steam = true;
        self.sync_all();

        let gen_id = self.gen_id;
        let backend = self.backend.clone();
        self.backend.spawn(async move {
            let res = backend.update_steam_preset(tok, steam).await;
            let _ = slint::invoke_from_event_loop(move || {
                with_controller(gen_id, |c| {
                    c.busy_steam = false;
                    c.allowing_blocked = None;
                    match res {
                        Ok(snap) => {
                            c.snapshot = Some(snap);
                            if let Some(msg) = success_toast {
                                if let Some(w) = c.window() {
                                    w.set_active_tab(0);
                                }
                                c.show_toast(msg);
                            }
                        }
                        Err(e) => c.show_toast(e),
                    }
                    c.sync_all();
                });
            });
        });
    }

    fn mutate_rule<F: FnOnce(&mut Rule)>(&mut self, id_str: &str, f: F) {
        let Some(tok) = self.require_token() else {
            return;
        };
        let Ok(id) = Uuid::parse_str(id_str) else {
            return;
        };
        if self.busy_rules.contains(&id) || self.deleting_rule == Some(id) {
            return;
        }
        let Some(mut rule) = self
            .snapshot
            .as_ref()
            .and_then(|s| s.config.rules.iter().find(|r| r.id == id))
            .cloned()
        else {
            return;
        };
        f(&mut rule);
        self.upsert_rule(tok, rule, false);
    }

    fn upsert_rule(&mut self, tok: String, rule: Rule, close_sheet_on_ok: bool) {
        let id = rule.id;
        let name = rule.name.clone();
        self.busy_rules.insert(id);
        if close_sheet_on_ok {
            self.saving_rule = true;
        }
        self.sync_all();

        let gen_id = self.gen_id;
        let backend = self.backend.clone();
        self.backend.spawn(async move {
            let res = backend.upsert_rule(tok, rule).await;
            let _ = slint::invoke_from_event_loop(move || {
                with_controller(gen_id, |c| {
                    c.busy_rules.remove(&id);
                    c.saving_rule = false;
                    match res {
                        Ok(snap) => {
                            c.snapshot = Some(snap);
                            if close_sheet_on_ok {
                                if let Some(w) = c.window() {
                                    w.set_screen(2);
                                    w.set_active_tab(0);
                                }
                            }
                            c.show_toast(format!("Saved {name}"));
                        }
                        Err(e) => c.show_toast(e),
                    }
                    c.sync_all();
                });
            });
        });
    }

    fn handle_delete_rule(&mut self, id_str: &str) {
        let Some(tok) = self.require_token() else {
            return;
        };
        let Ok(id) = Uuid::parse_str(id_str) else {
            return;
        };
        if self.deleting_rule.is_some() || self.busy_rules.contains(&id) {
            return;
        }
        self.deleting_rule = Some(id);
        self.sync_all();

        let gen_id = self.gen_id;
        let backend = self.backend.clone();
        self.backend.spawn(async move {
            let res = backend.delete_rule(tok, id).await;
            let _ = slint::invoke_from_event_loop(move || {
                with_controller(gen_id, |c| {
                    c.deleting_rule = None;
                    match res {
                        Ok(snap) => {
                            c.snapshot = Some(snap);
                            c.show_toast("Removed rule");
                        }
                        Err(e) => c.show_toast(e),
                    }
                    c.sync_all();
                });
            });
        });
    }

    fn open_add_domain_prompt(&mut self, id_str: &str) {
        if self.require_token().is_none() {
            return;
        }
        let Ok(id) = Uuid::parse_str(id_str) else {
            return;
        };
        let Some(win) = self.window() else { return };
        self.prompt_purpose = PromptPurpose::AddDomain(id);
        win.set_prompt_title("Add Allowed Website".into());
        win.set_prompt_description(
            "Allow this app to connect to a specific domain or wildcard pattern.".into(),
        );
        win.set_prompt_placeholder("*.example.com".into());
        win.set_prompt_submit_label("Add".into());
        win.set_prompt_busy_label("Saving…".into());
        win.set_prompt_mono(true);
        win.set_prompt_value(SharedString::default());
        win.set_prompt_error(SharedString::default());
        win.set_prompt_busy(false);
        win.set_prompt_open(true);
        win.invoke_focus_prompt();
    }

    fn handle_remove_domain(&mut self, id_str: &str, idx: i32) {
        if idx < 0 {
            return;
        }
        let idx = idx as usize;
        self.mutate_rule(id_str, |r| {
            let mut list = r.network.dns_whitelist.clone().unwrap_or_default();
            if idx < list.len() {
                list.remove(idx);
            }
            r.network.dns_whitelist = if list.is_empty() { None } else { Some(list) };
        });
    }

    fn handle_allow_blocked(&mut self, id_str: &str) {
        let Some(tok) = self.require_token() else {
            return;
        };
        if self.allowing_blocked.is_some() {
            return;
        }
        let Ok(id) = Uuid::parse_str(id_str) else {
            return;
        };
        let Some((ev, steam)) = self.snapshot.as_ref().and_then(|s| {
            let ev = s.blocked_events.iter().find(|e| e.id == id)?.clone();
            Some((ev, s.config.presets.steam.clone()))
        }) else {
            return;
        };

        if ev.is_steam_community {
            self.allowing_blocked = Some(ev.id);
            let mut next_steam = steam;
            next_steam.enabled = true;
            next_steam.community_and_workshop = true;
            self.update_steam_preset(tok, next_steam, Some("Enabled Steam Community"));
            return;
        }

        if !ev.path.is_empty() {
            self.allowing_blocked = Some(ev.id);
            self.sync_all();
            let path = ev.path;
            let gen_id = self.gen_id;
            let backend = self.backend.clone();
            self.backend.spawn(async move {
                let res = backend.inspect_executable(path).await;
                let _ = slint::invoke_from_event_loop(move || {
                    with_controller(gen_id, |c| {
                        c.allowing_blocked = None;
                        c.sync_all();
                        match res {
                            Ok(identity) => {
                                let pre = identity_to_running_app(identity);
                                c.enter_allow_sheet_with(Some(pre));
                            }
                            Err(e) => {
                                c.show_toast(format!("Could not read file: {e}"));
                                c.enter_allow_sheet_with(None);
                            }
                        }
                    });
                });
            });
            return;
        }

        self.open_allow_sheet();
    }

    // ---------- Settings Actions ----------

    fn handle_set_mode(&mut self, mode_idx: i32) {
        let Some(tok) = self.require_token() else {
            return;
        };
        if self.pending_mode.is_some() {
            return;
        }
        let (mode, toast_msg) = match mode_idx {
            0 => (EnforcementMode::Enforcing, "Protection on"),
            1 => (
                EnforcementMode::PausedUntil {
                    until: Utc::now() + ChronoDuration::minutes(15),
                },
                "Paused for 15 minutes",
            ),
            _ => (EnforcementMode::Disabled, "Protection off"),
        };

        self.pending_mode = Some(mode_idx);
        self.sync_all();

        let gen_id = self.gen_id;
        let backend = self.backend.clone();
        self.backend.spawn(async move {
            let res = backend.set_mode(tok, mode).await;
            let _ = slint::invoke_from_event_loop(move || {
                with_controller(gen_id, |c| {
                    c.pending_mode = None;
                    match res {
                        Ok(snap) => {
                            c.snapshot = Some(snap);
                            c.show_toast(toast_msg);
                        }
                        Err(e) => c.show_toast(e),
                    }
                    c.sync_all();
                });
            });
        });
    }

    fn mutate_baseline<F: FnOnce(&mut BaselinePolicy)>(&mut self, f: F) {
        let Some(tok) = self.require_token() else {
            return;
        };
        if self.busy_baseline {
            return;
        }
        let Some(mut baseline) = self.snapshot.as_ref().map(|s| s.config.baseline.clone()) else {
            return;
        };
        f(&mut baseline);
        self.busy_baseline = true;
        self.sync_all();

        let gen_id = self.gen_id;
        let backend = self.backend.clone();
        self.backend.spawn(async move {
            let res = backend.update_baseline(tok, baseline).await;
            let _ = slint::invoke_from_event_loop(move || {
                with_controller(gen_id, |c| {
                    c.busy_baseline = false;
                    match res {
                        Ok(snap) => c.snapshot = Some(snap),
                        Err(e) => c.show_toast(e),
                    }
                    c.sync_all();
                });
            });
        });
    }

    fn handle_upgrade_to_full(&mut self) {
        let Some(win) = self.window() else { return };
        if win.get_upgrading() {
            return;
        }
        let was_full = self
            .snapshot
            .as_ref()
            .is_some_and(|s| s.protection_tier == ProtectionTier::FullService);
        win.set_upgrading(true);

        let gen_id = self.gen_id;
        let backend = self.backend.clone();
        self.backend.spawn(async move {
            let res = backend.setup_full_protection().await;
            let _ = slint::invoke_from_event_loop(move || {
                with_controller(gen_id, |c| {
                    if let Some(w) = c.window() {
                        w.set_upgrading(false);
                    }
                    match res {
                        Ok(snap) => {
                            let needs_pw = !snap.password_configured;
                            c.snapshot = Some(snap);
                            c.sync_all();
                            c.show_toast(if was_full {
                                "Background service updated"
                            } else {
                                "Upgraded to Full Protection"
                            });
                            if needs_pw {
                                c.open_unlock_modal();
                            }
                        }
                        Err(e) => c.show_toast(e),
                    }
                });
            });
        });
    }

    fn handle_uninstall_service(&mut self) {
        if self.require_token().is_none() {
            return;
        }
        let Some(win) = self.window() else { return };
        if win.get_uninstalling() {
            return;
        }
        win.set_uninstalling(true);

        let gen_id = self.gen_id;
        let backend = self.backend.clone();
        self.backend.spawn(async move {
            let res = backend.uninstall_full_protection().await;
            let _ = slint::invoke_from_event_loop(move || {
                with_controller(gen_id, |c| {
                    if let Some(w) = c.window() {
                        w.set_uninstalling(false);
                    }
                    match res {
                        Ok(()) => {
                            c.token = None;
                            c.refresh_snapshot();
                            c.show_toast("System service removed");
                        }
                        Err(e) => c.show_toast(e),
                    }
                });
            });
        });
    }

    fn handle_toggle_pw_form(&mut self) {
        if self.require_token().is_none() {
            return;
        }
        let Some(win) = self.window() else { return };
        let next = !win.get_pw_open();
        win.set_pw_error(SharedString::default());
        win.set_pw_current(SharedString::default());
        win.set_pw_new(SharedString::default());
        win.set_pw_confirm(SharedString::default());
        win.set_pw_show(false);
        win.set_pw_open(next);
    }

    fn handle_change_password(&mut self, current: String, next: String, confirm: String) {
        let Some(tok) = self.require_token() else {
            return;
        };
        let Some(win) = self.window() else { return };
        if win.get_pw_busy() {
            return;
        }
        let configured = self
            .snapshot
            .as_ref()
            .map(|s| s.password_configured)
            .unwrap_or(true);

        if configured && current.is_empty() {
            win.set_pw_error("Enter your current Curb password.".into());
            return;
        }
        if next.len() < 4 {
            win.set_pw_error("New password must be at least 4 characters.".into());
            return;
        }
        if next != confirm {
            win.set_pw_error("New passwords do not match.".into());
            return;
        }

        win.set_pw_error(SharedString::default());
        win.set_pw_busy(true);

        let gen_id = self.gen_id;
        let backend = self.backend.clone();
        self.backend.spawn(async move {
            let res = backend.change_password(tok, current, next).await;
            let _ = slint::invoke_from_event_loop(move || {
                with_controller(gen_id, |c| {
                    if let Some(w) = c.window() {
                        w.set_pw_busy(false);
                        match res {
                            Ok(()) => {
                                w.set_pw_current(SharedString::default());
                                w.set_pw_new(SharedString::default());
                                w.set_pw_confirm(SharedString::default());
                                w.set_pw_show(false);
                                w.set_pw_open(false);
                                c.refresh_snapshot();
                                c.show_toast("Curb password updated");
                            }
                            Err(e) => w.set_pw_error(e.into()),
                        }
                    }
                });
            });
        });
    }

    // ---------- Allow App Picker Actions ----------

    fn open_allow_sheet(&mut self) {
        if self.require_token().is_none() {
            self.pending_open_allow = true;
            return;
        }
        self.enter_allow_sheet();
    }

    fn enter_allow_sheet(&mut self) {
        self.enter_allow_sheet_with(None);
    }

    fn enter_allow_sheet_with(&mut self, preselected: Option<RunningAppInfo>) {
        self.search.clear();
        self.selected_key = preselected.as_ref().map(|p| p.key.clone());
        self.browsed = preselected;
        self.inspect_error = None;
        self.inspecting_path = None;
        self.saving_rule = false;

        if let Some(win) = self.window() {
            win.set_picker_tab(0);
            win.set_picker_search(SharedString::default());
            win.set_picker_adv_open(false);
            win.set_picker_allow_tcp(true);
            win.set_picker_allow_udp(true);
            win.set_picker_sub_policy(1);
            win.set_picker_force_hash(false);
            win.set_picker_dns_text(SharedString::default());
            win.set_screen(3);
        }
        self.sync_picker();
        self.refresh_picker_sources();
    }

    fn close_allow_sheet(&mut self) {
        if let Some(win) = self.window() {
            win.set_screen(2);
        }
    }

    fn refresh_picker_sources(&mut self) {
        self.refresh_running_apps();
        self.refresh_steam_games();
    }

    fn refresh_running_apps(&mut self) {
        self.running_req_id += 1;
        let req_id = self.running_req_id;
        self.loading_running = true;
        self.sync_picker();

        let gen_id = self.gen_id;
        let backend = self.backend.clone();
        self.backend.spawn(async move {
            let res = backend.list_running_apps().await;
            let _ = slint::invoke_from_event_loop(move || {
                with_controller(gen_id, |c| {
                    if c.running_req_id != req_id {
                        return;
                    }
                    c.loading_running = false;
                    match res {
                        Ok(apps) => c.running_apps = apps,
                        Err(e) => c.show_toast(format!("Could not list running apps: {e}")),
                    }
                    c.sync_picker();
                });
            });
        });
    }

    fn refresh_steam_games(&mut self) {
        self.steam_req_id += 1;
        let req_id = self.steam_req_id;
        self.loading_steam = true;
        self.sync_picker();

        let gen_id = self.gen_id;
        let backend = self.backend.clone();
        self.backend.spawn(async move {
            let res = backend.list_steam_games().await;
            let _ = slint::invoke_from_event_loop(move || {
                with_controller(gen_id, |c| {
                    if c.steam_req_id != req_id {
                        return;
                    }
                    c.loading_steam = false;
                    match res {
                        Ok(games) => c.steam_games = games,
                        Err(e) => c.show_toast(format!("Could not scan Steam games: {e}")),
                    }
                    c.sync_picker();
                });
            });
        });
    }

    fn select_picker_entry(&mut self, key: String) {
        self.selected_key = Some(key);
        self.inspect_error = None;
        if let Some(sel) = self.selected_summary() {
            if sel.sha256.is_empty() {
                self.ensure_verified(sel.path);
            } else {
                self.inspect_req_id += 1;
                self.inspecting_path = None;
                self.sync_picker();
            }
        } else {
            self.sync_picker();
        }
    }

    fn retry_inspect_selected(&mut self) {
        if let Some(sel) = self.selected_summary() {
            let norm = sel.path.to_ascii_lowercase();
            self.inspected_by_path.remove(&norm);
            self.ensure_verified(sel.path);
        }
    }

    fn ensure_verified(&mut self, path: String) {
        let norm = path.to_ascii_lowercase();
        if self.inspected_by_path.contains_key(&norm) {
            self.inspect_error = None;
            self.sync_picker();
            return;
        }
        self.inspect_req_id += 1;
        let req_id = self.inspect_req_id;
        self.inspecting_path = Some(norm.clone());
        self.inspect_error = None;
        self.sync_picker();

        let gen_id = self.gen_id;
        let backend = self.backend.clone();
        self.backend.spawn(async move {
            let res = backend.inspect_executable(path).await;
            let _ = slint::invoke_from_event_loop(move || {
                with_controller(gen_id, |c| {
                    if c.inspect_req_id == req_id {
                        c.inspecting_path = None;
                    }
                    match res {
                        Ok(id) => {
                            let info = identity_to_running_app(id);
                            c.inspected_by_path.insert(norm, info);
                        }
                        Err(e) => {
                            if c.inspect_req_id == req_id {
                                c.inspect_error = Some("Could not verify executable on disk.".into());
                            }
                            c.show_toast(format!("Could not read file: {e}"));
                        }
                    }
                    c.sync_picker();
                });
            });
        });
    }

    fn open_browse_prompt(&mut self) {
        let Some(win) = self.window() else { return };
        if win.get_picker_browsing() || self.saving_rule {
            return;
        }
        self.prompt_purpose = PromptPurpose::BrowseExe;
        win.set_prompt_title("Add Executable by Path".into());
        let (prompt_desc, prompt_placeholder) = crate::elevate::exe_path_prompt();
        win.set_prompt_description(prompt_desc.into());
        win.set_prompt_placeholder(prompt_placeholder.into());
        win.set_prompt_submit_label("Inspect File".into());
        win.set_prompt_busy_label("Inspecting…".into());
        win.set_prompt_mono(true);
        win.set_prompt_value(SharedString::default());
        win.set_prompt_error(SharedString::default());
        win.set_prompt_busy(false);
        win.set_prompt_open(true);
        win.invoke_focus_prompt();
    }

    fn handle_submit_prompt(&mut self, raw: String) {
        let Some(win) = self.window() else { return };
        if win.get_prompt_busy() {
            return;
        }
        let purpose = self.prompt_purpose.clone();
        match purpose {
            PromptPurpose::None => {}
            PromptPurpose::AddDomain(rule_id) => {
                let cleaned = raw.trim().to_string();
                if cleaned.is_empty() {
                    win.set_prompt_error("Please enter a website pattern.".into());
                    return;
                }
                self.close_prompt_modal();
                self.mutate_rule(&rule_id.to_string(), |r| {
                    let mut list = r.network.dns_whitelist.clone().unwrap_or_default();
                    list.push(cleaned);
                    r.network.dns_whitelist = Some(list);
                });
            }
            PromptPurpose::BrowseExe => {
                let cleaned = raw.trim().trim_matches('"').trim().to_string();
                if cleaned.is_empty() {
                    win.set_prompt_error("Please enter the full path to an executable.".into());
                    return;
                }
                win.set_prompt_error(SharedString::default());
                win.set_prompt_busy(true);
                win.set_picker_browsing(true);

                let gen_id = self.gen_id;
                let backend = self.backend.clone();
                self.backend.spawn(async move {
                    let res = backend.inspect_executable(cleaned).await;
                    let _ = slint::invoke_from_event_loop(move || {
                        with_controller(gen_id, |c| {
                            if let Some(w) = c.window() {
                                w.set_prompt_busy(false);
                                w.set_picker_browsing(false);
                            }
                            match res {
                                Ok(id) => {
                                    let info = identity_to_running_app(id);
                                    c.selected_key = Some(info.key.clone());
                                    c.browsed = Some(info);
                                    c.inspect_error = None;
                                    c.close_prompt_modal();
                                    c.sync_picker();
                                }
                                Err(_) => {
                                    if let Some(w) = c.window() {
                                        w.set_prompt_error(
                                            "Could not read that executable. Check the path and try again.".into(),
                                        );
                                    }
                                }
                            }
                        });
                    });
                });
            }
        }
    }

    fn handle_confirm_allow(&mut self) {
        let Some(tok) = self.require_token() else {
            return;
        };
        let Some(win) = self.window() else { return };
        let Some(sel) = self.selected_summary() else {
            return;
        };
        if sel.sha256.is_empty() || self.saving_rule || self.inspecting_path.is_some() {
            return;
        }

        let allow_tcp = win.get_picker_allow_tcp();
        let allow_udp = win.get_picker_allow_udp();
        let sub_policy = int_to_subprocess(win.get_picker_sub_policy());
        let force_hash = win.get_picker_force_hash();
        let dns_raw = win.get_picker_dns_text().to_string();
        let dns_list: Vec<String> = dns_raw
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let use_signed = sel.signed && !force_hash && sel.signer.is_some();

        let matcher = if sel.is_steam {
            if let (Some(app_id), Some(install_dir)) = (sel.app_id, sel.install_dir) {
                ExecutableMatcher::SteamGame {
                    app_id,
                    install_dir,
                    verification: if use_signed {
                        VerificationMethod::Signature {
                            subject_cn: sel.signer.clone().unwrap(),
                            issuer_cn: None,
                            product_name: None,
                            original_filename: Some(sel.exe.clone()),
                        }
                    } else {
                        VerificationMethod::Hash {
                            sha256: sel.sha256.clone(),
                            filename_hint: sel.exe.clone(),
                        }
                    },
                }
            } else {
                ExecutableMatcher::Hash {
                    sha256: sel.sha256.clone(),
                    filename_hint: sel.exe.clone(),
                }
            }
        } else if use_signed {
            ExecutableMatcher::Signature {
                subject_cn: sel.signer.clone().unwrap(),
                issuer_cn: None,
                product_name: None,
                original_filename: Some(sel.exe.clone()),
            }
        } else {
            ExecutableMatcher::Hash {
                sha256: sel.sha256.clone(),
                filename_hint: sel.exe.clone(),
            }
        };

        let rule = Rule {
            id: Uuid::new_v4(),
            name: sel.name,
            enabled: true,
            matcher,
            network: NetworkPolicy {
                allow_tcp,
                allow_udp,
                dns_whitelist: if dns_list.is_empty() {
                    None
                } else {
                    Some(dns_list)
                },
            },
            subprocesses: sub_policy,
            exe_hint: sel.exe,
            exe_path: Some(sel.path),
            created_at: Utc::now(),
        };

        self.upsert_rule(tok, rule, true);
    }
}

fn identity_to_running_app(id: BinaryIdentity) -> RunningAppInfo {
    let fallback_name = id
        .filename
        .strip_suffix(".exe")
        .or_else(|| id.filename.strip_suffix(".EXE"))
        .unwrap_or(&id.filename)
        .to_string();
    let signed = id.signature.as_ref().map(|s| s.trusted).unwrap_or(false);
    let signer = id.signature.map(|s| s.subject_cn);
    RunningAppInfo {
        key: format!("browse-{}", id.path.to_ascii_lowercase()),
        name: id.product_name.unwrap_or(fallback_name),
        exe: id.filename,
        path: id.path,
        process_count: 1,
        background: false,
        tried_connect: false,
        tried_host: None,
        signed,
        signer,
        sha256: id.sha256,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initials_and_avatar_colors_match_expected() {
        assert_eq!(initials_for("Obsidian"), "OB");
        assert_eq!(initials_for("Deep Rock Galactic"), "DR");
        assert_eq!(initials_for("  Prism Launcher "), "PL");
        let _ = avatar_color_for("Obsidian");
    }

    #[test]
    fn steam_summary_formats_toggles() {
        let off = SteamPresetConfig {
            enabled: false,
            store_and_library: true,
            community_and_workshop: true,
            friends_and_voice: true,
        };
        assert_eq!(steam_summary(&off), "Blocked");

        let on = SteamPresetConfig {
            enabled: true,
            store_and_library: true,
            community_and_workshop: false,
            friends_and_voice: true,
        };
        assert_eq!(steam_summary(&on), "Downloads · Store · Friends");
    }

    #[test]
    fn subprocess_policy_roundtrip() {
        for p in [
            SubprocessPolicy::Disabled,
            SubprocessPolicy::SameSignerOrDir,
            SubprocessPolicy::AnyExceptRestricted,
        ] {
            assert_eq!(int_to_subprocess(subprocess_to_int(p)), p);
        }
    }
}
