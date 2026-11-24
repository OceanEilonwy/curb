use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use chrono::Utc;
use curb_core::auth::{hash_password, verify_password, AuthRecord, SessionManager};
use curb_core::config::{Config, NetworkPolicy};
use curb_core::dns::{domain_matches_any, DnsCache};
use curb_core::ipc::{
    record_grouped_blocked_event, BlockedEvent, IpcRequest, IpcResponse, ServiceSnapshot,
    MAX_BLOCKED_HISTORY,
};
use curb_core::presets::EffectiveRule;
use curb_core::processes::collect_running_apps;
use curb_core::steam::{discover_steam_games, find_default_steam_root};
use curb_core::store::{load_auth, load_config, save_auth, save_config};
use curb_core::verify::{inspect_binary, BinaryIdentity};
use tokio::sync::Notify;

/// Microsoft NCSI probe domains used by Windows to verify internet connectivity
/// and keep Wi-Fi / Ethernet adapters from showing "No Internet" or bouncing.
pub const NCSI_DOMAINS: &[&str] = &[
    "www.msftconnecttest.com",
    "ipv6.msftconnecttest.com",
    "dns.msftncsi.com",
    "www.msftncsi.com",
    "ipv6.msftncsi.com",
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
}

impl EngineState {
    pub fn load(data_dir: PathBuf) -> curb_core::Result<Self> {
        let config = load_config(&data_dir)?;
        let auth = load_auth(&data_dir)?;
        Ok(Self {
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
        })
    }

    /// Compiles all enabled presets and user rules into flat `EffectiveRule`s.
    pub fn effective_rules(&self) -> Vec<EffectiveRule> {
        let mut out = self.config.presets.steam.expand_rules();
        for rule in &self.config.rules {
            if rule.enabled {
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
            if !rule.enabled {
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
                for exe in curb_core::steam::collect_game_executables(std::path::Path::new(install_dir)) {
                    let s = exe.to_string_lossy().to_string();
                    if !paths.iter().any(|x| x.eq_ignore_ascii_case(&s)) {
                        paths.push(s);
                    }
                }
            }
        }

        if self.config.presets.steam.enabled {
            if let Some(root) = find_default_steam_root() {
                for rel in [
                    "steam.exe",
                    r"bin\steamservice.exe",
                    r"bin\cef\cef.win7x64\steamwebhelper.exe",
                    r"bin\cef\steamwebhelper.exe",
                ] {
                    let candidate = root.join(rel);
                    if candidate.exists() {
                        let s = candidate.to_string_lossy().to_string();
                        if !paths.iter().any(|x| x.eq_ignore_ascii_case(&s)) {
                            paths.push(s);
                        }
                    }
                }
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
            let ntp = ["time.windows.com".to_string(), "*.pool.ntp.org".to_string()];
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
        ServiceSnapshot {
            config: self.config.clone(),
            password_configured: self.auth.is_some(),
            blocked_events: self.blocked_events.iter().cloned().collect(),
            active_wfp_filters: self.active_wfp_filters,
            protection_tier: curb_core::ipc::ProtectionTier::FullService,
            service_version: env!("CARGO_PKG_VERSION").to_string(),
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
    pub reconcile_notify: Arc<Notify>,
    pub dns_v4_ready: Arc<AtomicBool>,
    pub dns_v6_ready: Arc<AtomicBool>,
    pub wfp_loop_active: Arc<AtomicBool>,
    wfp_dns_sync_tx: Arc<tokio::sync::watch::Sender<u64>>,
    wfp_dns_sync_rx: tokio::sync::watch::Receiver<u64>,
}

impl ServiceEngine {
    pub fn new(data_dir: PathBuf) -> curb_core::Result<Self> {
        let (wfp_dns_sync_tx, wfp_dns_sync_rx) = tokio::sync::watch::channel(0u64);
        Ok(Self {
            state: Arc::new(Mutex::new(EngineState::load(data_dir)?)),
            reconcile_notify: Arc::new(Notify::new()),
            dns_v4_ready: Arc::new(AtomicBool::new(false)),
            dns_v6_ready: Arc::new(AtomicBool::new(false)),
            wfp_loop_active: Arc::new(AtomicBool::new(false)),
            wfp_dns_sync_tx: Arc::new(wfp_dns_sync_tx),
            wfp_dns_sync_rx,
        })
    }

    pub fn notify_reconcile(&self) {
        self.reconcile_notify.notify_one();
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
                let apps = collect_running_apps(&blocked_snapshot, visible_pids.as_deref());
                IpcResponse::RunningApps { apps }
            }

            IpcRequest::ListSteamGames => {
                let games = find_default_steam_root()
                    .and_then(|root| discover_steam_games(&root).ok())
                    .unwrap_or_default();
                IpcResponse::SteamGames { games }
            }

            IpcRequest::InspectExecutable { path } => match inspect_binary(std::path::Path::new(&path)) {
                Ok(identity) => IpcResponse::Inspected { identity },
                Err(e) => IpcResponse::Error {
                    message: format!("Could not inspect file: {e}"),
                },
            },

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
                if let Some(record) = &guard.auth {
                    if !verify_password(&current_password, record) {
                        return IpcResponse::Error {
                            message: "Current password is incorrect.".into(),
                        };
                    }
                }
                match hash_password(&new_password) {
                    Ok(new_record) => {
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
        if let Err(e) = save_config(&guard.data_dir, &guard.config) {
            return IpcResponse::Error {
                message: format!("Failed to persist config: {e}"),
            };
        }
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
}
