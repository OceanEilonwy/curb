use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Duration as ChronoDuration, Local, Utc};
use curb_core::auth::{hash_password, verify_password, AuthRecord, SessionManager};
use curb_core::config::{Config, ExecutableMatcher, NetworkPolicy};
use curb_core::dns::{domain_matches_any, DnsCache};
use curb_core::ipc::{
    record_grouped_blocked_event, BlockedEvent, IpcRequest, IpcResponse, ServiceSnapshot,
    MAX_BLOCKED_HISTORY,
};
use curb_core::playtime::{PlaytimeChipState, PlaytimeRuleStatus, UsageLedger};
use curb_core::presets::{DefaultPresetHost, EffectiveRule, PresetHost, PresetRegistry};
use curb_core::store::{
    load_auth, load_config, load_sync_config, load_usage, peer_identity_path, save_auth,
    save_config, save_sync_config, save_usage,
};
use curb_core::sync::{
    generate_invite_code, InviteKind, InviteToken, RelayConnectionState, RemoteStatus,
    RemoteSyncConfig, DEFAULT_RELAY_URL,
};
use curb_core::verify::BinaryIdentity;
use curb_p2p::PeerIdentity;
use curb_preset_steam::SteamPresetPlugin;
use tokio::sync::Notify;
use uuid::Uuid;

/// Builds the default built-in preset plugin registry (register new presets here).
pub fn default_preset_registry() -> Arc<PresetRegistry> {
    let mut reg = PresetRegistry::new();
    reg.register(Arc::new(SteamPresetPlugin));
    Arc::new(reg)
}

/// OS connectivity-check probe domains (Windows NCSI + Linux NetworkManager/ConnMan)
/// used to keep Wi-Fi / Ethernet adapters from showing "No Internet" or "Limited".
pub const NCSI_DOMAINS: &[&str] = &[
    // Windows NCSI
    "www.msftconnecttest.com",
    "ipv6.msftconnecttest.com",
    "dns.msftncsi.com",
    "www.msftncsi.com",
    "ipv6.msftncsi.com",
    // Linux NetworkManager / ConnMan connectivity checks
    "ping.archlinux.org",
    "fedoraproject.org",
    "connectivity-check.ubuntu.com",
    "nmcheck.gnome.org",
    "networkcheck.kde.org",
    "ipv4.connman.net",
];

/// Represents an allowed running process currently tracked by `curb-service`.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct TrackedProcess {
    pub pid: u32,
    pub identity: BinaryIdentity,
    pub rule_label: String,
    pub network: NetworkPolicy,
    pub allow_subprocesses: curb_core::config::SubprocessPolicy,
    pub dynamic_filter_ids: Vec<u64>,
}

/// In-memory single-use invite issued by an unlocked admin (10-minute TTL).
#[derive(Debug, Clone)]
pub struct PendingInvite {
    pub kind: InviteKind,
    pub expires_at: DateTime<Utc>,
}

/// Central mutable state shared across IPC, DNS proxy, and enforcement loops.
pub struct EngineState {
    pub data_dir: PathBuf,
    pub config: Config,
    pub config_version: u64,
    pub auth: Option<AuthRecord>,
    pub sessions: SessionManager,
    pub dns_cache: DnsCache,
    pub upstream_dns: Vec<SocketAddr>,
    pub blocked_events: VecDeque<BlockedEvent>,
    pub tracked_processes: HashMap<u32, TrackedProcess>,
    pub active_wfp_filters: usize,
    pub presets: Arc<PresetRegistry>,
    pub preset_host: Arc<dyn PresetHost>,
    pub usage_ledger: UsageLedger,
    pub playtime_statuses: HashMap<Uuid, PlaytimeRuleStatus>,
    pub sync_config: RemoteSyncConfig,
    pub peer_identity: PeerIdentity,
    pub pending_invites: HashMap<String, PendingInvite>,
    pub relay_state: RelayConnectionState,
    pub relay_error: Option<String>,
}

impl EngineState {
    #[allow(dead_code)]
    pub fn load(data_dir: PathBuf) -> curb_core::Result<Self> {
        Self::load_with_presets(
            data_dir,
            default_preset_registry(),
            Arc::new(DefaultPresetHost::default()),
        )
    }

    pub fn load_with_presets(
        data_dir: PathBuf,
        presets: Arc<PresetRegistry>,
        preset_host: Arc<dyn PresetHost>,
    ) -> curb_core::Result<Self> {
        let config = load_config(&data_dir)?;
        let auth = load_auth(&data_dir)?;
        let usage_ledger = load_usage(&data_dir).unwrap_or_default();
        let sync_config = load_sync_config(&data_dir)
            .unwrap_or_else(|_| RemoteSyncConfig::new_default("This PC"));
        let peer_identity = PeerIdentity::load_or_create(&peer_identity_path(&data_dir))
            .unwrap_or_else(|_| PeerIdentity::generate());
        let initial_relay_state = if sync_config.relay_url.trim().is_empty() {
            RelayConnectionState::Disabled
        } else {
            RelayConnectionState::Connecting
        };
        let mut st = Self {
            data_dir,
            config,
            config_version: 0,
            auth,
            sessions: SessionManager::default(),
            dns_cache: DnsCache::new(),
            upstream_dns: Vec::new(),
            blocked_events: VecDeque::with_capacity(MAX_BLOCKED_HISTORY),
            tracked_processes: HashMap::new(),
            active_wfp_filters: 0,
            presets,
            preset_host,
            usage_ledger,
            playtime_statuses: HashMap::new(),
            sync_config,
            peer_identity,
            pending_invites: HashMap::new(),
            relay_state: initial_relay_state,
            relay_error: None,
        };
        st.refresh_playtime_statuses();
        Ok(st)
    }

    /// Returns `true` if `rule_id` currently has its internet access cut due to an
    /// exhausted playtime limit (`Overtime` state while global limits are enabled).
    pub fn is_rule_playtime_expired(&self, rule_id: Uuid) -> bool {
        if !self.config.playtime_limits_enabled {
            return false;
        }
        self.playtime_statuses
            .get(&rule_id)
            .is_some_and(|s| s.limits_active && s.chip_state == PlaytimeChipState::Overtime)
    }

    /// Recomputes `playtime_statuses` from `config` + `usage_ledger` (called on load,
    /// config mutations, and admin resets).
    pub fn refresh_playtime_statuses(&mut self) {
        let now_local = Local::now();
        let registry = curb_games::DetectorRegistry::default();
        let mut next = HashMap::new();

        for rule in &self.config.rules {
            let app_id = match &rule.matcher {
                ExecutableMatcher::SteamGame { app_id, .. } => Some(*app_id),
                _ => None,
            };
            let fc_info = app_id.and_then(|id| registry.info(id));
            let first_class = fc_info.is_some();
            let detector_name = fc_info.map(|i| i.plugin_name.to_string());
            let prev_telemetry = self
                .playtime_statuses
                .get(&rule.id)
                .and_then(|s| s.live_telemetry.clone());

            if let Some(limit) = &rule.playtime_limit {
                let limits_active =
                    rule.enabled && self.config.playtime_limits_enabled && limit.enabled;
                let (remaining_today_secs, daily_budget_secs, is_exempt_today) = self
                    .usage_ledger
                    .remaining_today(rule.id, limit, now_local);
                let rec = self.usage_ledger.rules.get(&rule.id);
                let (used_today_secs, overtime_debt_secs, draining, expired) = rec
                    .map(|r| {
                        (
                            r.used_today_secs,
                            r.overtime_debt_secs.saturating_add(r.active_overtime_secs),
                            r.draining_match,
                            r.expired_today,
                        )
                    })
                    .unwrap_or((0, 0, false, false));

                let chip_state = if !limits_active || is_exempt_today {
                    PlaytimeChipState::Playing
                } else if draining {
                    PlaytimeChipState::FinishingMatch
                } else if expired || remaining_today_secs == 0 {
                    PlaytimeChipState::Overtime
                } else {
                    PlaytimeChipState::Playing
                };

                next.insert(
                    rule.id,
                    PlaytimeRuleStatus {
                        rule_id: rule.id,
                        chip_state,
                        limits_active,
                        is_exempt_today,
                        daily_budget_secs,
                        remaining_today_secs,
                        used_today_secs,
                        overtime_debt_secs,
                        first_class,
                        detector_name,
                        live_telemetry: prev_telemetry,
                    },
                );
            } else if first_class {
                next.insert(
                    rule.id,
                    PlaytimeRuleStatus {
                        rule_id: rule.id,
                        chip_state: PlaytimeChipState::Playing,
                        limits_active: false,
                        is_exempt_today: false,
                        daily_budget_secs: 0,
                        remaining_today_secs: 0,
                        used_today_secs: 0,
                        overtime_debt_secs: 0,
                        first_class,
                        detector_name,
                        live_telemetry: prev_telemetry,
                    },
                );
            }
        }

        self.playtime_statuses = next;
    }

    /// Compiles all enabled presets and user rules into flat `EffectiveRule`s,
    /// excluding any game whose playtime limit is currently in `Overtime` (internet cut).
    pub fn effective_rules(&self) -> Vec<EffectiveRule> {
        let mut out = self
            .presets
            .expand_all_rules(&self.config.presets, self.preset_host.target_os());
        for rule in &self.config.rules {
            if rule.enabled && !self.is_rule_playtime_expired(rule.id) {
                out.push(EffectiveRule {
                    label: rule.name.clone(),
                    matcher: rule.matcher.clone(),
                    network: rule.network.clone(),
                    subprocesses: rule.subprocesses,
                });
            }
        }
        out
    }

    /// Evaluates whether a newly spawned process should be permitted on the network.
    pub fn evaluate_process(
        &self,
        parent_pid: Option<u32>,
        identity: &BinaryIdentity,
    ) -> Option<(String, NetworkPolicy, curb_core::config::SubprocessPolicy)> {
        if !self.config.mode.is_actively_enforcing(Utc::now()) {
            return Some((
                "Protection paused/disabled".into(),
                NetworkPolicy::default(),
                curb_core::config::SubprocessPolicy::AnyExceptRestricted,
            ));
        }

        // 1. Direct match against active presets and user rules.
        for rule in self.effective_rules() {
            if rule.matcher.matches(identity) {
                return Some((rule.label, rule.network, rule.subprocesses));
            }
        }

        // 2. Sub-process inheritance from an already allowed parent process.
        if let Some(ppid) = parent_pid {
            if let Some(parent) = self.tracked_processes.get(&ppid) {
                if parent
                    .allow_subprocesses
                    .allows_child(&parent.identity, identity)
                {
                    return Some((
                        format!("{} (helper)", parent.rule_label),
                        parent.network.clone(),
                        parent.allow_subprocesses,
                    ));
                }
            }
        }

        // 3. Install-directory helper inheritance for apps/games whose initial launcher
        // stub process already exited (leaving an orphaned parent_pid on Windows).
        if !curb_core::config::is_restricted_subprocess(&identity.filename) {
            for rule in &self.config.rules {
                if !rule.enabled
                    || self.is_rule_playtime_expired(rule.id)
                    || rule.subprocesses == curb_core::config::SubprocessPolicy::Disabled
                {
                    continue;
                }
                if let curb_core::config::ExecutableMatcher::SteamGame { install_dir, .. } =
                    &rule.matcher
                {
                    if path_is_within_dir(&identity.path, install_dir) {
                        return Some((
                            format!("{} (helper)", rule.name),
                            rule.network.clone(),
                            rule.subprocesses,
                        ));
                    }
                }
                if let Some(rule_exe) = &rule.exe_path {
                    if let Some(rule_dir) = parent_dir_normalized(rule_exe) {
                        if path_is_within_normalized_dir(&identity.path, &rule_dir) {
                            return Some((
                                format!("{} (helper)", rule.name),
                                rule.network.clone(),
                                rule.subprocesses,
                            ));
                        }
                    }
                }
            }
        }

        None
    }

    /// Returns known on-disk executable paths for enabled rules and presets so
    /// Curb can proactively install their WFP `ALE_APP_ID` permit filters with
    /// 0ms startup delay (before the process even launches or across restarts).
    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn candidate_rule_paths(&self) -> Vec<String> {
        let mut paths = Vec::new();
        for rule in &self.config.rules {
            if !rule.enabled || self.is_rule_playtime_expired(rule.id) {
                continue;
            }
            if let Some(p) = &rule.exe_path {
                if !p.is_empty() && !paths.iter().any(|x: &String| x.eq_ignore_ascii_case(p)) {
                    paths.push(p.clone());
                }
            }
            if let curb_core::config::ExecutableMatcher::SteamGame { install_dir, .. } =
                &rule.matcher
            {
                for exe in curb_core::steam::collect_game_executables_with(
                    std::path::Path::new(install_dir),
                    |p| self.preset_host.is_executable(p),
                ) {
                    let s = exe.to_string_lossy().to_string();
                    if !paths.iter().any(|x| x.eq_ignore_ascii_case(&s)) {
                        paths.push(s);
                    }
                }
            }
        }

        for candidate in self
            .presets
            .collect_candidate_paths(&self.config.presets, self.preset_host.as_ref())
        {
            let s = candidate.to_string_lossy().to_string();
            if !paths.iter().any(|x| x.eq_ignore_ascii_case(&s)) {
                paths.push(s);
            }
        }

        paths
    }

    /// Returns true if `domain` is permitted to be resolved by Curb's local DNS proxy.
    pub fn is_dns_query_allowed(&self, domain: &str) -> bool {
        if !self.config.mode.is_actively_enforcing(Utc::now()) {
            return true;
        }

        let origin = self.dns_cache.origin_for_domain(domain);

        // Allow Windows NCSI probe domains when baseline NCSI is enabled.
        if self.config.baseline.ncsi {
            let ncsi: Vec<String> = NCSI_DOMAINS.iter().map(|s| (*s).to_string()).collect();
            if domain_matches_any(domain, &ncsi)
                || origin.as_deref().is_some_and(|o| domain_matches_any(o, &ncsi))
            {
                return true;
            }
        }

        // Allow NTP pools if baseline NTP is enabled.
        if self.config.baseline.ntp {
            let ntp = [
                "time.windows.com".to_string(),
                "*.pool.ntp.org".to_string(),
                "*.ntp.org".to_string(),
                "ntp.ubuntu.com".to_string(),
                "time.cloudflare.com".to_string(),
                "time.nist.gov".to_string(),
            ];
            if domain_matches_any(domain, &ntp)
                || origin.as_deref().is_some_and(|o| domain_matches_any(o, &ntp))
            {
                return true;
            }
        }

        let rules = self.effective_rules();
        // If any active rule has a DNS whitelist matching this domain (or its CNAME origin), allow resolution.
        for rule in &rules {
            if let Some(patterns) = &rule.network.dns_whitelist {
                if domain_matches_any(domain, patterns)
                    || origin
                        .as_deref()
                        .is_some_and(|o| domain_matches_any(o, patterns))
                {
                    return true;
                }
            }
        }

        // If any active unrestricted rule exists (e.g. a multiplayer game or steam.exe),
        // DNS resolution is allowed here while WFP still blocks non-whitelisted apps from
        // connecting to any resolved IPs.
        rules.iter().any(|r| r.network.dns_whitelist.is_none())
    }

    /// Computes the currently resolved IP set for a rule with a DNS whitelist.
    pub fn allowed_ips_for_network(&self, net: &NetworkPolicy) -> Option<Vec<IpAddr>> {
        net.dns_whitelist
            .as_ref()
            .map(|patterns| self.dns_cache.allowed_ips_for_patterns(patterns))
    }

    /// Computes currently resolved IPs for Windows NCSI connectivity probes.
    pub fn ncsi_allowed_ips(&self) -> Vec<IpAddr> {
        if !self.config.baseline.ncsi {
            return Vec::new();
        }
        let patterns: Vec<String> = NCSI_DOMAINS.iter().map(|s| (*s).to_string()).collect();
        self.dns_cache.allowed_ips_for_patterns(&patterns)
    }

    pub fn record_blocked_event(&mut self, event: BlockedEvent) {
        record_grouped_blocked_event(&mut self.blocked_events, event, MAX_BLOCKED_HISTORY);
    }

    pub fn snapshot(&self) -> ServiceSnapshot {
        let mut playtime_statuses = Vec::new();
        for rule in &self.config.rules {
            if let Some(st) = self.playtime_statuses.get(&rule.id) {
                playtime_statuses.push(st.clone());
            }
        }
        let remote_status = RemoteStatus {
            device_name: self.sync_config.device_name.clone(),
            peer_id: self.peer_identity.peer_id(),
            relay_url: self.sync_config.relay_url.clone(),
            relay_connected: self.relay_state == RelayConnectionState::Connected,
            relay_state: self.relay_state,
            relay_error: self.relay_error.clone(),
            encrypted_backup_enabled: self.sync_config.encrypted_backup_enabled,
            revision: self.sync_config.revision,
            admins: self
                .auth
                .as_ref()
                .map(|a| a.admin_summaries())
                .unwrap_or_default(),
            synced_devices: self.sync_config.synced_devices.clone(),
        };
        ServiceSnapshot {
            config: self.config.clone(),
            password_configured: self.auth.is_some(),
            blocked_events: self.blocked_events.iter().cloned().collect(),
            active_wfp_filters: self.active_wfp_filters,
            protection_tier: curb_core::ipc::ProtectionTier::FullService,
            service_version: env!("CARGO_PKG_VERSION").to_string(),
            playtime_statuses,
            remote_status,
        }
    }
}

fn parent_dir_normalized(path: &str) -> Option<String> {
    let norm = path.replace('\\', "/").to_ascii_lowercase();
    let (mut dir, _) = norm.rsplit_once('/')?;
    if dir.is_empty() {
        return None;
    }
    // If the executable resides inside a Squirrel/Electron/Edge versioned subfolder
    // (e.g. `.../discord/app-1.0.9175/discord.exe` or `.../Application/131.0.2903.70/msedge.exe`),
    // normalize to the parent application directory so `Update.exe` and newly updated
    // `app-*` subfolders are matched as helpers when `subprocesses != Disabled`.
    if let Some((parent_dir, leaf)) = dir.rsplit_once('/') {
        let is_version_dir = leaf.starts_with("app-")
            || (leaf.chars().next().is_some_and(|c| c.is_ascii_digit()) && leaf.contains('.'));
        let parent_depth = parent_dir.split('/').filter(|s| !s.is_empty()).count();
        if is_version_dir && parent_depth >= 3 {
            dir = parent_dir;
        }
    }
    // Avoid matching broad root or system directories if a binary sits directly in them.
    let depth = dir.split('/').filter(|s| !s.is_empty()).count();
    if depth < 2 {
        return None;
    }
    Some(format!("{dir}/"))
}

fn path_is_within_dir(exe_path: &str, dir_path: &str) -> bool {
    let mut norm_dir = dir_path
        .replace('\\', "/")
        .trim_end_matches('/')
        .to_ascii_lowercase();
    if norm_dir.is_empty() {
        return false;
    }
    norm_dir.push('/');
    path_is_within_normalized_dir(exe_path, &norm_dir)
}

fn path_is_within_normalized_dir(exe_path: &str, norm_dir_with_slash: &str) -> bool {
    let norm_exe = exe_path.replace('\\', "/").to_ascii_lowercase();
    norm_exe.starts_with(norm_dir_with_slash)
}

/// Thread-safe handle to `EngineState` with IPC request dispatch.
#[derive(Clone)]
pub struct ServiceEngine {
    pub state: Arc<Mutex<EngineState>>,
    pub adaptors: curb_core::adaptors::ServiceAdaptors,
    pub reconcile_notify: Arc<Notify>,
    pub dns_refresh_notify: Arc<Notify>,
    pub relay_notify: Arc<Notify>,
    pub dns_v4_ready: Arc<AtomicBool>,
    pub dns_v6_ready: Arc<AtomicBool>,
    pub wfp_loop_active: Arc<AtomicBool>,
    wfp_dns_sync_tx: Arc<tokio::sync::watch::Sender<u64>>,
    wfp_dns_sync_rx: tokio::sync::watch::Receiver<u64>,
}

impl ServiceEngine {
    #[allow(dead_code)]
    pub fn new(data_dir: PathBuf) -> curb_core::Result<Self> {
        Self::with_adaptors(data_dir, curb_core::adaptors::ServiceAdaptors::default())
    }

    pub fn with_adaptors(
        data_dir: PathBuf,
        adaptors: curb_core::adaptors::ServiceAdaptors,
    ) -> curb_core::Result<Self> {
        let (wfp_dns_sync_tx, wfp_dns_sync_rx) = tokio::sync::watch::channel(0u64);
        Ok(Self {
            state: Arc::new(Mutex::new(EngineState::load_with_presets(
                data_dir,
                default_preset_registry(),
                adaptors.preset_host.clone(),
            )?)),
            adaptors,
            reconcile_notify: Arc::new(Notify::new()),
            dns_refresh_notify: Arc::new(Notify::new()),
            relay_notify: Arc::new(Notify::new()),
            dns_v4_ready: Arc::new(AtomicBool::new(false)),
            dns_v6_ready: Arc::new(AtomicBool::new(false)),
            wfp_loop_active: Arc::new(AtomicBool::new(false)),
            wfp_dns_sync_tx: Arc::new(wfp_dns_sync_tx),
            wfp_dns_sync_rx,
        })
    }

    pub fn set_relay_status(&self, state: RelayConnectionState, error: Option<String>) {
        let mut guard = self.state.lock().unwrap();
        guard.relay_state = state;
        guard.relay_error = error;
    }

    pub fn notify_reconcile(&self) {
        self.reconcile_notify.notify_one();
    }

    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn notify_dns_refresh(&self) {
        self.dns_refresh_notify.notify_one();
    }

    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn set_wfp_loop_active(&self, active: bool) {
        self.wfp_loop_active.store(active, Ordering::Release);
    }

    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn mark_wfp_dns_applied(&self, dns_version: u64) {
        self.wfp_dns_sync_tx.send_if_modified(|current| {
            if *current != dns_version {
                *current = dns_version;
                true
            } else {
                false
            }
        });
    }

    /// Waits until the WFP enforcement loop has installed permit filters for at least
    /// `target_version` of `DnsCache` (or `timeout` elapses). Returns immediately when
    /// WFP enforcement is not active (e.g. non-Windows or paused mode).
    pub async fn wait_for_wfp_dns_sync(&self, target_version: u64, timeout: std::time::Duration) {
        if !self.wfp_loop_active.load(Ordering::Acquire) {
            return;
        }
        let mut rx = self.wfp_dns_sync_rx.clone();
        if *rx.borrow_and_update() >= target_version {
            return;
        }
        let _ = tokio::time::timeout(timeout, async {
            while rx.changed().await.is_ok() {
                if *rx.borrow() >= target_version {
                    break;
                }
            }
        })
        .await;
    }

    pub fn set_dns_ready(&self, v4: bool, v6: bool) {
        self.dns_v4_ready.store(v4, Ordering::Release);
        self.dns_v6_ready.store(v6, Ordering::Release);
    }

    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn is_dns_v4_ready(&self) -> bool {
        self.dns_v4_ready.load(Ordering::Acquire)
    }

    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn is_dns_v6_ready(&self) -> bool {
        self.dns_v6_ready.load(Ordering::Acquire)
    }

    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn set_upstream_dns(&self, servers: Vec<SocketAddr>) {
        let mut guard = self.state.lock().unwrap();
        guard.upstream_dns = servers;
    }

    /// Returns upstream DNS resolvers ordered by preference:
    /// 1. Original adapter DNS servers captured before Curb redirected DNS
    /// 2. Configured fallback resolver (default `1.1.1.1:53`)
    /// 3. Secondary public fallback (`8.8.8.8:53`)
    pub fn upstream_dns_servers(&self, fallback: SocketAddr) -> Vec<SocketAddr> {
        let mut out = {
            let guard = self.state.lock().unwrap();
            guard.upstream_dns.clone()
        };
        if !out.contains(&fallback) {
            out.push(fallback);
        }
        let secondary = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);
        if !out.contains(&secondary) {
            out.push(secondary);
        }
        out
    }

    pub fn handle_request(&self, req: IpcRequest) -> IpcResponse {
        match req {
            IpcRequest::GetSnapshot => {
                let guard = self.state.lock().unwrap();
                IpcResponse::Snapshot {
                    data: guard.snapshot(),
                }
            }

            IpcRequest::ListRunningApps { visible_pids } => {
                let blocked_snapshot = {
                    let guard = self.state.lock().unwrap();
                    guard.blocked_events.iter().cloned().collect::<Vec<_>>()
                };
                let apps = self
                    .adaptors
                    .processes
                    .collect_running_apps(&blocked_snapshot, visible_pids.as_deref());
                IpcResponse::RunningApps { apps }
            }

            IpcRequest::ListSteamGames => {
                let presets = self.state.lock().unwrap().presets.clone();
                let games = presets
                    .get(curb_preset_steam::STEAM_PRESET_ID)
                    .and_then(|p| p.discover_items(self.adaptors.preset_host.as_ref()).ok())
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(SteamPresetPlugin::to_discovered_steam_game)
                    .collect();
                IpcResponse::SteamGames { games }
            }

            IpcRequest::ListPresets => {
                let presets = self.state.lock().unwrap().presets.descriptors();
                IpcResponse::Presets { presets }
            }

            IpcRequest::DiscoverPresetItems { preset_id } => {
                let presets = self.state.lock().unwrap().presets.clone();
                let items = presets
                    .get(&preset_id)
                    .and_then(|p| p.discover_items(self.adaptors.preset_host.as_ref()).ok())
                    .unwrap_or_default();
                IpcResponse::PresetItems { items }
            }

            IpcRequest::UpdatePreset {
                token,
                preset_id,
                state,
            } => self.mutate_config(&token, |cfg| {
                cfg.presets.set_state(&preset_id, state);
            }),

            IpcRequest::InspectExecutable { path } => {
                match self.adaptors.verifier.inspect_binary(std::path::Path::new(&path)) {
                    Ok(identity) => IpcResponse::Inspected { identity },
                    Err(e) => IpcResponse::Error {
                        message: format!("Could not inspect file: {e}"),
                    },
                }
            }

            IpcRequest::Unlock { password } => {
                let mut guard = self.state.lock().unwrap();
                let Some(record) = guard.auth.clone() else {
                    // First-run setup: allow setting initial password if none configured yet.
                    return match hash_password(&password) {
                        Ok(new_record) => {
                            if let Err(e) = save_auth(&guard.data_dir, &new_record) {
                                return IpcResponse::Error {
                                    message: format!("Failed to save password: {e}"),
                                };
                            }
                            let token = guard.sessions.unlock(&password, &new_record).unwrap();
                            guard.auth = Some(new_record);
                            IpcResponse::Unlocked { token }
                        }
                        Err(e) => IpcResponse::Error {
                            message: e.to_string(),
                        },
                    };
                };

                match guard.sessions.unlock(&password, &record) {
                    Ok(token) => IpcResponse::Unlocked { token },
                    Err(e) => IpcResponse::Error {
                        message: e.to_string(),
                    },
                }
            }

            IpcRequest::Lock { token } => {
                let mut guard = self.state.lock().unwrap();
                guard.sessions.lock(&token);
                IpcResponse::Ok
            }

            IpcRequest::SetMode { token, mode } => {
                self.mutate_config(&token, |cfg| {
                    cfg.mode = mode;
                })
            }

            IpcRequest::UpdateSteamPreset { token, steam } => {
                self.mutate_config(&token, |cfg| {
                    cfg.presets.steam = steam;
                })
            }

            IpcRequest::UpdateBaseline { token, baseline } => {
                self.mutate_config(&token, |cfg| {
                    cfg.baseline = baseline;
                })
            }

            IpcRequest::UpsertRule { token, rule } => {
                self.mutate_config(&token, |cfg| {
                    if let Some(existing) = cfg.rules.iter_mut().find(|r| r.id == rule.id) {
                        *existing = rule;
                    } else {
                        cfg.rules.insert(0, rule);
                    }
                })
            }

            IpcRequest::DeleteRule { token, id } => {
                self.mutate_config(&token, |cfg| {
                    cfg.rules.retain(|r| r.id != id);
                })
            }

            IpcRequest::SetPlaytimeLimitsEnabled { token, enabled } => {
                self.mutate_config(&token, |cfg| {
                    cfg.playtime_limits_enabled = enabled;
                })
            }

            IpcRequest::ResetPlaytimeLimit { token, rule_id } => {
                let mut guard = self.state.lock().unwrap();
                if !guard.sessions.validate_and_refresh(&token) {
                    return IpcResponse::Error {
                        message: "Admin session locked or expired. Please unlock again.".into(),
                    };
                }
                guard.usage_ledger.reset_rule(rule_id, Local::now());
                guard.refresh_playtime_statuses();
                guard.config_version = guard.config_version.wrapping_add(1);
                if let Err(e) = save_usage(&guard.data_dir, &guard.usage_ledger) {
                    return IpcResponse::Error {
                        message: format!("Failed to persist usage: {e}"),
                    };
                }
                let snapshot = guard.snapshot();
                drop(guard);
                self.notify_reconcile();
                IpcResponse::Snapshot { data: snapshot }
            }

            IpcRequest::ResetAllPlaytimeLimits { token } => {
                let mut guard = self.state.lock().unwrap();
                if !guard.sessions.validate_and_refresh(&token) {
                    return IpcResponse::Error {
                        message: "Admin session locked or expired. Please unlock again.".into(),
                    };
                }
                guard.usage_ledger.reset_all(Local::now());
                guard.refresh_playtime_statuses();
                guard.config_version = guard.config_version.wrapping_add(1);
                if let Err(e) = save_usage(&guard.data_dir, &guard.usage_ledger) {
                    return IpcResponse::Error {
                        message: format!("Failed to persist usage: {e}"),
                    };
                }
                let snapshot = guard.snapshot();
                drop(guard);
                self.notify_reconcile();
                IpcResponse::Snapshot { data: snapshot }
            }

            IpcRequest::ChangePassword {
                token,
                current_password,
                new_password,
            } => {
                let mut guard = self.state.lock().unwrap();
                if !guard.sessions.validate_and_refresh(&token) {
                    return IpcResponse::Error {
                        message: "Admin session expired. Please unlock again.".into(),
                    };
                }
                let existing_admins = if let Some(record) = &guard.auth {
                    if !verify_password(&current_password, record) {
                        return IpcResponse::Error {
                            message: "Current password is incorrect.".into(),
                        };
                    }
                    record.admins.clone()
                } else {
                    Vec::new()
                };
                match hash_password(&new_password) {
                    Ok(mut new_record) => {
                        new_record.admins = existing_admins;
                        if let Err(e) = save_auth(&guard.data_dir, &new_record) {
                            return IpcResponse::Error {
                                message: format!("Failed to save password: {e}"),
                            };
                        }
                        guard.auth = Some(new_record);
                        guard.sessions.lock_all_except(&token);
                        IpcResponse::Ok
                    }
                    Err(e) => IpcResponse::Error {
                        message: e.to_string(),
                    },
                }
            }

            IpcRequest::UnlockAsPeer { peer_id, password } => {
                let mut guard = self.state.lock().unwrap();
                let Some(record) = guard.auth.clone() else {
                    return IpcResponse::Error {
                        message: "No admin password is configured on this device.".into(),
                    };
                };
                match guard.sessions.unlock_as_peer(&peer_id, &password, &record) {
                    Ok((token, admin_id)) => {
                        let data_dir = guard.data_dir.clone();
                        if let Some(auth) = guard.auth.as_mut() {
                            if let Some(adm) = auth.admins.iter_mut().find(|a| a.id == admin_id) {
                                adm.last_unlock_at = Some(Utc::now());
                            }
                            let _ = save_auth(&data_dir, auth);
                        }
                        IpcResponse::Unlocked { token }
                    }
                    Err(e) => IpcResponse::Error {
                        message: e.to_string(),
                    },
                }
            }

            IpcRequest::RenameDevice { token, name } => {
                let mut guard = self.state.lock().unwrap();
                if !guard.sessions.validate_and_refresh(&token) {
                    return IpcResponse::Error {
                        message: "Admin session locked or expired. Please unlock again.".into(),
                    };
                }
                let trimmed = name.trim().to_string();
                if trimmed.is_empty() {
                    return IpcResponse::Error {
                        message: "Device name cannot be empty.".into(),
                    };
                }
                guard.sync_config.device_name = trimmed;
                guard.sync_config.revision = guard.sync_config.revision.saturating_add(1);
                if let Err(e) = save_sync_config(&guard.data_dir, &guard.sync_config) {
                    return IpcResponse::Error {
                        message: format!("Failed to save device name: {e}"),
                    };
                }
                IpcResponse::Snapshot {
                    data: guard.snapshot(),
                }
            }

            IpcRequest::CreateInvite { token, kind } => {
                let mut guard = self.state.lock().unwrap();
                if !guard.sessions.validate_and_refresh(&token) {
                    return IpcResponse::Error {
                        message: "Admin session locked or expired. Please unlock again.".into(),
                    };
                }
                // Auto-enable default relay if none configured yet so invites work out of the box.
                if guard.sync_config.relay_url.trim().is_empty() {
                    guard.sync_config.relay_url = DEFAULT_RELAY_URL.to_string();
                    guard.relay_state = RelayConnectionState::Connecting;
                    guard.relay_error = None;
                    let _ = save_sync_config(&guard.data_dir, &guard.sync_config);
                    self.relay_notify.notify_waiters();
                }
                let now = Utc::now();
                guard.pending_invites.retain(|_, inv| inv.expires_at > now);

                let code = generate_invite_code();
                let expires_in_secs = 600u64;
                guard.pending_invites.insert(
                    code.clone(),
                    PendingInvite {
                        kind,
                        expires_at: now + ChronoDuration::seconds(expires_in_secs as i64),
                    },
                );
                let invite = InviteToken {
                    kind,
                    target_peer_id: guard.peer_identity.peer_id(),
                    relay_url: guard.sync_config.relay_url.clone(),
                    code: code.clone(),
                    device_name: guard.sync_config.device_name.clone(),
                    direct_addr: None,
                };
                IpcResponse::InviteCreated {
                    uri: invite.to_uri(),
                    code,
                    expires_in_secs,
                }
            }

            IpcRequest::RedeemInvite {
                code,
                peer_id,
                name,
                password,
            } => {
                let mut guard = self.state.lock().unwrap();
                let now = Utc::now();
                guard.pending_invites.retain(|_, inv| inv.expires_at > now);

                let Some(invite) = guard.pending_invites.remove(code.trim()) else {
                    return IpcResponse::Error {
                        message: "Invite code is invalid or expired.".into(),
                    };
                };

                let data_dir = guard.data_dir.clone();
                let mut group_key_hex = None;
                match invite.kind {
                    InviteKind::FriendAdmin => {
                        let Some(auth) = guard.auth.as_mut() else {
                            return IpcResponse::Error {
                                message: "This device has not completed initial setup yet.".into(),
                            };
                        };
                        if let Err(e) = auth.add_admin(name, Some(peer_id), &password) {
                            return IpcResponse::Error {
                                message: e.to_string(),
                            };
                        }
                        if let Err(e) = save_auth(&data_dir, auth) {
                            return IpcResponse::Error {
                                message: format!("Failed to save friend admin: {e}"),
                            };
                        }
                    }
                    InviteKind::SyncDevice => {
                        let applied_rev = guard.sync_config.revision;
                        group_key_hex = Some(guard.sync_config.group_key_hex.clone());
                        guard.sync_config.synced_devices.retain(|d| d.peer_id != peer_id);
                        guard.sync_config.synced_devices.push(
                            curb_core::sync::SyncedDeviceInfo {
                                peer_id,
                                name: if name.trim().is_empty() {
                                    "Linked Device".into()
                                } else {
                                    name.trim().to_string()
                                },
                                os: "Synced".into(),
                                online: true,
                                last_seen_at: now,
                                applied_revision: applied_rev,
                            },
                        );
                    }
                }
                guard.sync_config.revision = guard.sync_config.revision.saturating_add(1);
                let _ = save_sync_config(&data_dir, &guard.sync_config);

                IpcResponse::InviteRedeemed {
                    device_name: guard.sync_config.device_name.clone(),
                    peer_id: guard.peer_identity.peer_id(),
                    group_key_hex,
                }
            }

            IpcRequest::RemoveAdmin { token, admin_id } => {
                let mut guard = self.state.lock().unwrap();
                if !guard.sessions.validate_and_refresh(&token) {
                    return IpcResponse::Error {
                        message: "Admin session locked or expired. Please unlock again.".into(),
                    };
                }
                let data_dir = guard.data_dir.clone();
                let removed = if let Some(auth) = guard.auth.as_mut() {
                    if auth.remove_admin(admin_id) {
                        if let Err(e) = save_auth(&data_dir, auth) {
                            return IpcResponse::Error {
                                message: format!("Failed to save admin list: {e}"),
                            };
                        }
                        true
                    } else {
                        false
                    }
                } else {
                    false
                };
                if removed {
                    guard.sessions.lock_all_except(&token);
                    guard.sync_config.revision = guard.sync_config.revision.saturating_add(1);
                    let _ = save_sync_config(&data_dir, &guard.sync_config);
                }
                IpcResponse::Snapshot {
                    data: guard.snapshot(),
                }
            }

            IpcRequest::SetRelayConfig {
                token,
                relay_url,
                encrypted_backup_enabled,
            } => {
                let mut guard = self.state.lock().unwrap();
                if !guard.sessions.validate_and_refresh(&token) {
                    return IpcResponse::Error {
                        message: "Admin session locked or expired. Please unlock again.".into(),
                    };
                }
                let trimmed = relay_url.trim().to_string();
                let url_changed = guard.sync_config.relay_url != trimmed;
                guard.sync_config.relay_url = trimmed.clone();
                guard.sync_config.encrypted_backup_enabled = encrypted_backup_enabled;
                if trimmed.is_empty() {
                    guard.relay_state = RelayConnectionState::Disabled;
                    guard.relay_error = None;
                } else if url_changed || guard.relay_state != RelayConnectionState::Connected {
                    guard.relay_state = RelayConnectionState::Connecting;
                    guard.relay_error = None;
                }
                if let Err(e) = save_sync_config(&guard.data_dir, &guard.sync_config) {
                    return IpcResponse::Error {
                        message: format!("Failed to save sync settings: {e}"),
                    };
                }
                self.relay_notify.notify_waiters();
                IpcResponse::Snapshot {
                    data: guard.snapshot(),
                }
            }

            IpcRequest::RetryRelayConnection => {
                let mut guard = self.state.lock().unwrap();
                if guard.sync_config.relay_url.trim().is_empty() {
                    guard.relay_state = RelayConnectionState::Disabled;
                    guard.relay_error = None;
                } else {
                    guard.relay_state = RelayConnectionState::Connecting;
                    guard.relay_error = None;
                    self.relay_notify.notify_waiters();
                }
                IpcResponse::Snapshot {
                    data: guard.snapshot(),
                }
            }
        }
    }

    fn mutate_config<F>(&self, token: &str, update: F) -> IpcResponse
    where
        F: FnOnce(&mut Config),
    {
        let mut guard = self.state.lock().unwrap();
        if !guard.sessions.validate_and_refresh(token) {
            return IpcResponse::Error {
                message: "Admin session locked or expired. Please unlock again.".into(),
            };
        }
        update(&mut guard.config);
        guard.config_version = guard.config_version.wrapping_add(1);
        guard.sync_config.revision = guard.sync_config.revision.saturating_add(1);
        guard.refresh_playtime_statuses();
        if let Err(e) = save_config(&guard.data_dir, &guard.config) {
            return IpcResponse::Error {
                message: format!("Failed to persist config: {e}"),
            };
        }
        let _ = save_sync_config(&guard.data_dir, &guard.sync_config);
        let snapshot = guard.snapshot();
        drop(guard);
        self.notify_reconcile();
        IpcResponse::Snapshot { data: snapshot }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curb_core::config::EnforcementMode;
    use uuid::Uuid;

    #[test]
    fn ipc_rejects_mutations_without_valid_session_token() {
        let dir = std::env::temp_dir().join(format!("curb_engine_{}", Uuid::new_v4()));
        let engine = ServiceEngine::new(dir.clone()).unwrap();

        let resp = engine.handle_request(IpcRequest::SetMode {
            token: "fake-token".into(),
            mode: EnforcementMode::Disabled,
        });
        assert!(matches!(resp, IpcResponse::Error { .. }));

        let unlocked = engine.handle_request(IpcRequest::Unlock {
            password: "secret-password".into(),
        });
        let token = match unlocked {
            IpcResponse::Unlocked { token } => token,
            other => panic!("expected Unlocked, got {other:?}"),
        };

        let resp = engine.handle_request(IpcRequest::SetMode {
            token,
            mode: EnforcementMode::Disabled,
        });
        assert!(matches!(resp, IpcResponse::Snapshot { .. }));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn evaluates_direct_rules_subprocess_inheritance_and_dns_ips() {
        use curb_core::config::{ExecutableMatcher, SubprocessPolicy};
        use curb_core::verify::SignatureInfo;
        use std::net::Ipv4Addr;

        let dir = std::env::temp_dir().join(format!("curb_eval_{}", Uuid::new_v4()));
        let mut state = EngineState::load(dir.clone()).unwrap();

        // Steam preset is enabled by default with Store DNS whitelist.
        let webhelper = BinaryIdentity {
            path: r"C:\Program Files (x86)\Steam\bin\cef\steamwebhelper.exe".into(),
            filename: "steamwebhelper.exe".into(),
            sha256: "deadbeef".into(),
            signature: Some(SignatureInfo {
                trusted: true,
                subject_cn: "Valve Corp.".into(),
                issuer_cn: "DigiCert".into(),
            }),
            product_name: Some("Steam".into()),
            original_filename: Some("steamwebhelper.exe".into()),
            file_description: None,
        };

        let (label, net, _) = state
            .evaluate_process(None, &webhelper)
            .expect("steamwebhelper allowed via Steam preset");
        assert!(label.contains("Steam Web Helper"));

        let store_ip = IpAddr::V4(Ipv4Addr::new(23, 50, 1, 10));
        state.dns_cache.record("store.steampowered.com", &[store_ip], 120);
        let ips = state.allowed_ips_for_network(&net).expect("dns-scoped IPs");
        assert_eq!(ips, vec![store_ip]);

        // Track an allowed parent process and verify sub-process inheritance blocks Edge.
        let game = BinaryIdentity {
            path: r"D:\Games\DRG\game.exe".into(),
            filename: "game.exe".into(),
            sha256: "1122".into(),
            signature: Some(SignatureInfo {
                trusted: true,
                subject_cn: "Ghost Ship Games".into(),
                issuer_cn: "DigiCert".into(),
            }),
            product_name: Some("DRG".into()),
            original_filename: Some("game.exe".into()),
            file_description: None,
        };
        let helper = BinaryIdentity {
            path: r"D:\Games\DRG\helper.exe".into(),
            filename: "helper.exe".into(),
            sha256: "3344".into(),
            signature: None,
            product_name: None,
            original_filename: None,
            file_description: None,
        };
        let edge = BinaryIdentity {
            path: r"C:\Program Files\Edge\msedge.exe".into(),
            filename: "msedge.exe".into(),
            sha256: "5566".into(),
            signature: None,
            product_name: None,
            original_filename: None,
            file_description: None,
        };

        state.tracked_processes.insert(
            4242,
            TrackedProcess {
                pid: 4242,
                identity: game,
                rule_label: "DRG".into(),
                network: NetworkPolicy::default(),
                allow_subprocesses: SubprocessPolicy::SameSignerOrDir,
                dynamic_filter_ids: vec![1, 2],
            },
        );
        assert_eq!(state.tracked_processes[&4242].pid, 4242);
        assert!(state.evaluate_process(Some(4242), &helper).is_some());
        assert!(state.evaluate_process(Some(4242), &edge).is_none());

        let _unused = ExecutableMatcher::Hash {
            sha256: "00".into(),
            filename_hint: "a.exe".into(),
        };
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn allows_firefox_edge_signal_proactive_paths_and_orphaned_install_dir_helpers() {
        use curb_core::config::{ExecutableMatcher, Rule, SubprocessPolicy};
        use curb_core::verify::SignatureInfo;

        let dir = std::env::temp_dir().join(format!("curb_apps_{}", Uuid::new_v4()));
        let mut state = EngineState::load(dir.clone()).unwrap();

        let signal_path =
            r"C:\Users\alice\AppData\Local\Programs\signal-desktop\Signal.exe".to_string();
        let firefox_path = r"C:\Program Files\Mozilla Firefox\firefox.exe".to_string();
        let edge_path =
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe".to_string();

        state.config.rules = vec![
            Rule {
                id: Uuid::new_v4(),
                name: "Signal".into(),
                enabled: true,
                matcher: ExecutableMatcher::Signature {
                    subject_cn: "Signal Messenger, LLC".into(),
                    issuer_cn: None,
                    product_name: None,
                    original_filename: Some("Signal.exe".into()),
                },
                network: NetworkPolicy::default(),
                subprocesses: SubprocessPolicy::SameSignerOrDir,
                exe_hint: "Signal.exe".into(),
                exe_path: Some(signal_path.clone()),
                playtime_limit: None,
                created_at: Utc::now(),
            },
            Rule {
                id: Uuid::new_v4(),
                name: "Firefox".into(),
                enabled: true,
                matcher: ExecutableMatcher::Signature {
                    subject_cn: "Mozilla Corporation".into(),
                    issuer_cn: None,
                    product_name: None,
                    original_filename: Some("firefox.exe".into()),
                },
                network: NetworkPolicy::default(),
                subprocesses: SubprocessPolicy::SameSignerOrDir,
                exe_hint: "firefox.exe".into(),
                exe_path: Some(firefox_path.clone()),
                playtime_limit: None,
                created_at: Utc::now(),
            },
            Rule {
                id: Uuid::new_v4(),
                name: "Microsoft Edge".into(),
                enabled: true,
                matcher: ExecutableMatcher::Signature {
                    subject_cn: "Microsoft Corporation".into(),
                    issuer_cn: None,
                    product_name: None,
                    original_filename: Some("msedge.exe".into()),
                },
                network: NetworkPolicy::default(),
                subprocesses: SubprocessPolicy::SameSignerOrDir,
                exe_hint: "msedge.exe".into(),
                exe_path: Some(edge_path.clone()),
                playtime_limit: None,
                created_at: Utc::now(),
            },
        ];

        // Candidate paths should include all three enabled rule paths for proactive 0ms WFP filters
        let candidates = state.candidate_rule_paths();
        assert!(candidates.contains(&signal_path));
        assert!(candidates.contains(&firefox_path));
        assert!(candidates.contains(&edge_path));

        // Direct evaluation of Signal, Firefox, and Edge
        let signal_id = BinaryIdentity {
            path: signal_path,
            filename: "Signal.exe".into(),
            sha256: "111".into(),
            signature: Some(SignatureInfo {
                trusted: true,
                subject_cn: "Signal Messenger, LLC".into(),
                issuer_cn: "DigiCert".into(),
            }),
            product_name: None,
            original_filename: None,
            file_description: None,
        };
        assert!(state.evaluate_process(None, &signal_id).is_some());

        // Helper executable in Firefox's install folder when initial launcher stub PID (9999) already exited
        let firefox_helper = BinaryIdentity {
            path: r"C:\Program Files\Mozilla Firefox\plugin-container.exe".into(),
            filename: "plugin-container.exe".into(),
            sha256: "222".into(),
            signature: None,
            product_name: None,
            original_filename: None,
            file_description: None,
        };
        assert!(state.evaluate_process(Some(9999), &firefox_helper).is_some());

        // Unrelated app outside allowed install folders must remain blocked
        let chrome = BinaryIdentity {
            path: r"C:\Program Files\Google\Chrome\Application\chrome.exe".into(),
            filename: "chrome.exe".into(),
            sha256: "333".into(),
            signature: None,
            product_name: None,
            original_filename: None,
            file_description: None,
        };
        assert!(state.evaluate_process(Some(9999), &chrome).is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn change_password_verifies_current_and_rotates_sessions() {
        let dir = std::env::temp_dir().join(format!("curb_pw_{}", Uuid::new_v4()));
        let engine = ServiceEngine::new(dir.clone()).unwrap();

        // First unlock sets initial password
        let t1 = match engine.handle_request(IpcRequest::Unlock {
            password: "initial-pass".into(),
        }) {
            IpcResponse::Unlocked { token } => token,
            other => panic!("expected Unlocked, got {other:?}"),
        };

        // Open a second session
        let t2 = match engine.handle_request(IpcRequest::Unlock {
            password: "initial-pass".into(),
        }) {
            IpcResponse::Unlocked { token } => token,
            other => panic!("expected Unlocked, got {other:?}"),
        };

        // Wrong current password must fail
        let bad = engine.handle_request(IpcRequest::ChangePassword {
            token: t1.clone(),
            current_password: "wrong".into(),
            new_password: "new-password".into(),
        });
        assert!(matches!(bad, IpcResponse::Error { .. }));

        // Valid change succeeds
        let ok = engine.handle_request(IpcRequest::ChangePassword {
            token: t1.clone(),
            current_password: "initial-pass".into(),
            new_password: "new-password".into(),
        });
        assert!(matches!(ok, IpcResponse::Ok));

        // Caller's session remains valid, other session is revoked
        assert!(matches!(
            engine.handle_request(IpcRequest::SetMode {
                token: t1,
                mode: EnforcementMode::Enforcing,
            }),
            IpcResponse::Snapshot { .. }
        ));
        assert!(matches!(
            engine.handle_request(IpcRequest::SetMode {
                token: t2,
                mode: EnforcementMode::Disabled,
            }),
            IpcResponse::Error { .. }
        ));

        // Old password no longer unlocks; new password unlocks
        assert!(matches!(
            engine.handle_request(IpcRequest::Unlock {
                password: "initial-pass".into(),
            }),
            IpcResponse::Error { .. }
        ));
        assert!(matches!(
            engine.handle_request(IpcRequest::Unlock {
                password: "new-password".into(),
            }),
            IpcResponse::Unlocked { .. }
        ));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn wfp_dns_sync_waits_when_active_and_returns_immediately_when_inactive() {
        let dir = std::env::temp_dir().join(format!("curb_dns_sync_{}", Uuid::new_v4()));
        let engine = ServiceEngine::new(dir.clone()).unwrap();

        // Inactive loop should never block DNS replies.
        engine
            .wait_for_wfp_dns_sync(5, std::time::Duration::from_secs(2))
            .await;

        // Active loop should wait until mark_wfp_dns_applied reaches target_version.
        engine.set_wfp_loop_active(true);
        let eng_bg = engine.clone();
        let handle = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            eng_bg.mark_wfp_dns_applied(5);
        });

        let start = std::time::Instant::now();
        engine
            .wait_for_wfp_dns_sync(5, std::time::Duration::from_secs(2))
            .await;
        assert!(start.elapsed() < std::time::Duration::from_millis(500));
        handle.await.unwrap();

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn playtime_overtime_cuts_game_and_admin_reset_or_global_disable_restores_access() {
        use curb_core::config::{Rule, SubprocessPolicy, VerificationMethod};
        use curb_core::playtime::{PlaytimeBudget, PlaytimeLimitConfig};
        use curb_core::verify::SignatureInfo;

        let dir = std::env::temp_dir().join(format!("curb_playtime_{}", Uuid::new_v4()));
        let engine = ServiceEngine::new(dir.clone()).unwrap();
        let token = match engine.handle_request(IpcRequest::Unlock {
            password: "admin-secret".into(),
        }) {
            IpcResponse::Unlocked { token } => token,
            other => panic!("expected Unlocked, got {other:?}"),
        };

        let rule_id = Uuid::new_v4();
        let halo_rule = Rule {
            id: rule_id,
            name: "Halo: The Master Chief Collection".into(),
            enabled: true,
            matcher: ExecutableMatcher::SteamGame {
                app_id: 976730,
                install_dir: r"D:\SteamLibrary\steamapps\common\Halo The Master Chief Collection"
                    .into(),
                verification: VerificationMethod::Hash {
                    sha256: "halo-sha".into(),
                    filename_hint: "MCC-Win64-Shipping.exe".into(),
                },
            },
            network: NetworkPolicy::default(),
            subprocesses: SubprocessPolicy::SameSignerOrDir,
            exe_hint: "MCC-Win64-Shipping.exe".into(),
            exe_path: Some(
                r"D:\SteamLibrary\steamapps\common\Halo The Master Chief Collection\MCC\Binaries\Win64\MCC-Win64-Shipping.exe"
                    .into(),
            ),
            playtime_limit: Some(PlaytimeLimitConfig {
                enabled: true,
                budget: PlaytimeBudget::Daily { hours: 1.0 },
                wait_for_match_end: true,
                max_overtime_minutes: 30,
                carry_over_debt: true,
            }),
            created_at: Utc::now(),
        };

        let _ = engine.handle_request(IpcRequest::UpsertRule {
            token: token.clone(),
            rule: halo_rule,
        });

        let halo_bin = BinaryIdentity {
            path: r"D:\SteamLibrary\steamapps\common\Halo The Master Chief Collection\MCC\Binaries\Win64\MCC-Win64-Shipping.exe"
                .into(),
            filename: "MCC-Win64-Shipping.exe".into(),
            sha256: "halo-sha".into(),
            signature: None,
            product_name: None,
            original_filename: None,
            file_description: None,
        };
        let steam_bin = BinaryIdentity {
            path: r"C:\Program Files (x86)\Steam\steam.exe".into(),
            filename: "steam.exe".into(),
            sha256: "steam-sha".into(),
            signature: Some(SignatureInfo {
                trusted: true,
                subject_cn: "Valve Corp.".into(),
                issuer_cn: "DigiCert".into(),
            }),
            product_name: Some("Steam".into()),
            original_filename: Some("steam.exe".into()),
            file_description: None,
        };

        // Initially allowed (full 1h budget remaining) and recognized as first-class.
        {
            let guard = engine.state.lock().unwrap();
            assert!(guard.evaluate_process(None, &halo_bin).is_some());
            assert!(guard.playtime_statuses[&rule_id].first_class);
        }

        // Exhaust budget -> Overtime cuts Halo internet access while Steam stays online.
        {
            let mut guard = engine.state.lock().unwrap();
            let limit = guard.config.rules[0].playtime_limit.clone().unwrap();
            let chip = guard
                .usage_ledger
                .record_tick(rule_id, &limit, 3600, false, true, Local::now());
            assert_eq!(chip, PlaytimeChipState::Overtime);
            guard.refresh_playtime_statuses();
            assert!(guard.evaluate_process(None, &halo_bin).is_none());
            assert!(guard.evaluate_process(None, &steam_bin).is_some());
        }

        // Global disable restores Halo immediately without wiping usage.
        let _ = engine.handle_request(IpcRequest::SetPlaytimeLimitsEnabled {
            token: token.clone(),
            enabled: false,
        });
        assert!(engine
            .state
            .lock()
            .unwrap()
            .evaluate_process(None, &halo_bin)
            .is_some());

        // Re-enabling global limits cuts Halo again.
        let _ = engine.handle_request(IpcRequest::SetPlaytimeLimitsEnabled {
            token: token.clone(),
            enabled: true,
        });
        assert!(engine
            .state
            .lock()
            .unwrap()
            .evaluate_process(None, &halo_bin)
            .is_none());

        // Admin reset restores Halo immediately.
        let _ = engine.handle_request(IpcRequest::ResetPlaytimeLimit { token, rule_id });
        assert!(engine
            .state
            .lock()
            .unwrap()
            .evaluate_process(None, &halo_bin)
            .is_some());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn remote_admin_invite_rename_and_revocation_lifecycle() {
        let dir = std::env::temp_dir().join(format!("curb_remote_{}", Uuid::new_v4()));
        let auth = hash_password("owner-local-secret").unwrap();
        save_auth(&dir, &auth).unwrap();

        let engine = ServiceEngine::new(dir.clone()).unwrap();
        let local_token = match engine.handle_request(IpcRequest::Unlock {
            password: "owner-local-secret".into(),
        }) {
            IpcResponse::Unlocked { token } => token,
            other => panic!("Expected unlock, got {other:?}"),
        };

        // Rename device
        let renamed = engine.handle_request(IpcRequest::RenameDevice {
            token: local_token.clone(),
            name: "Jordan's PC".into(),
        });
        match renamed {
            IpcResponse::Snapshot { data } => {
                assert_eq!(data.remote_status.device_name, "Jordan's PC");
            }
            other => panic!("Expected snapshot after rename, got {other:?}"),
        }

        // Create single-use friend invite
        let (uri, code) = match engine.handle_request(IpcRequest::CreateInvite {
            token: local_token.clone(),
            kind: InviteKind::FriendAdmin,
        }) {
            IpcResponse::InviteCreated { uri, code, .. } => (uri, code),
            other => panic!("Expected InviteCreated, got {other:?}"),
        };
        let parsed = InviteToken::parse_uri(&uri).expect("valid invite URI");
        assert_eq!(parsed.device_name, "Jordan's PC");
        assert_eq!(parsed.code, code);

        // Friend redeems invite and sets their own personal password
        let friend_peer = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
        let redeemed = engine.handle_request(IpcRequest::RedeemInvite {
            code: code.clone(),
            peer_id: friend_peer.into(),
            name: "Alex".into(),
            password: "alex-own-password".into(),
        });
        assert!(matches!(
            redeemed,
            IpcResponse::InviteRedeemed { device_name, .. } if device_name == "Jordan's PC"
        ));

        // Reusing the burned one-time invite code fails
        let replay = engine.handle_request(IpcRequest::RedeemInvite {
            code,
            peer_id: friend_peer.into(),
            name: "Eve".into(),
            password: "evil-password".into(),
        });
        assert!(matches!(replay, IpcResponse::Error { .. }));

        // Friend unlocks with their own password
        let friend_token = match engine.handle_request(IpcRequest::UnlockAsPeer {
            peer_id: friend_peer.into(),
            password: "alex-own-password".into(),
        }) {
            IpcResponse::Unlocked { token } => token,
            other => panic!("Expected friend unlock, got {other:?}"),
        };
        assert!(!friend_token.is_empty());

        // Revoke friend admin -> friend can no longer unlock
        let admin_id = match engine.handle_request(IpcRequest::GetSnapshot) {
            IpcResponse::Snapshot { data } => {
                assert_eq!(data.remote_status.admins.len(), 1);
                assert_eq!(data.remote_status.admins[0].name, "Alex");
                data.remote_status.admins[0].id
            }
            other => panic!("Expected snapshot, got {other:?}"),
        };
        let _ = engine.handle_request(IpcRequest::RemoveAdmin {
            token: local_token,
            admin_id,
        });
        let revoked_unlock = engine.handle_request(IpcRequest::UnlockAsPeer {
            peer_id: friend_peer.into(),
            password: "alex-own-password".into(),
        });
        assert!(matches!(revoked_unlock, IpcResponse::Error { .. }));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
