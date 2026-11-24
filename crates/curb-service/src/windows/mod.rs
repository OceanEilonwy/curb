#[cfg(windows)]
pub mod adapter_dns;
#[cfg(windows)]
pub mod etw;
#[cfg(windows)]
pub mod wfp;

#[cfg(windows)]
pub use runtime::run_windows_enforcement_loop;

#[cfg(windows)]
mod runtime {
    use std::collections::{HashMap, HashSet};
    use std::net::{IpAddr, SocketAddr};
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    use chrono::{DateTime, Utc};
    use curb_core::config::NetworkPolicy;
    use curb_core::ipc::BlockedEvent;
    use curb_core::store::save_config;
    use curb_core::verify::{inspect_binary, peek_binary, BinaryIdentity};
    use tracing::{info, warn};
    use uuid::Uuid;
    use windows::core::PWSTR;
    use windows::Win32::Foundation::{CloseHandle, BOOLEAN, FILETIME, HANDLE};
    use windows::Win32::NetworkManagement::IpHelper::{
        CancelMibChangeNotify2, NotifyIpInterfaceChange, MIB_IPINTERFACE_ROW,
        MIB_NOTIFICATION_TYPE,
    };
    use windows::Win32::Networking::WinSock::AF_UNSPEC;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    use crate::engine::{ServiceEngine, TrackedProcess};

    use super::adapter_dns::{enable_local_dns_redirect, restore_original_adapter_dns};
    use super::etw::ImageLockTable;
    use super::wfp::WfpController;

    /// How often to re-apply adapter DNS redirection as a periodic safety net.
    const DNS_REDIRECT_REFRESH: Duration = Duration::from_secs(300);
    /// Back-off before retrying a failed adapter DNS redirect.
    const DNS_REDIRECT_RETRY: Duration = Duration::from_secs(15);
    /// Minimum interval between event-driven DNS redirect refreshes (e.g. bursts of
    /// `NotifyIpInterfaceChange` events during Wi-Fi roaming or VPN connect).
    const DNS_EVENT_DEBOUNCE: Duration = Duration::from_secs(2);
    /// How often to refresh Microsoft NCSI probe IPs (well under their 600s cache TTL floor)
    /// so Windows never loses NCSI connectivity checks during WFP filter updates.
    const NCSI_PREWARM_REFRESH: Duration = Duration::from_secs(240);

    /// RAII guard for Windows `NotifyIpInterfaceChange` so network/VPN/Wi-Fi changes
    /// immediately wake Curb to re-apply `127.0.0.1` adapter DNS redirection.
    struct IpChangeSubscription {
        handle: HANDLE,
        notify_ptr: *const tokio::sync::Notify,
    }

    unsafe impl Send for IpChangeSubscription {}

    impl IpChangeSubscription {
        fn register(notify: std::sync::Arc<tokio::sync::Notify>) -> Option<Self> {
            unsafe extern "system" fn callback(
                caller_context: *const std::ffi::c_void,
                _row: *const MIB_IPINTERFACE_ROW,
                _notification_type: MIB_NOTIFICATION_TYPE,
            ) {
                if !caller_context.is_null() {
                    let n = &*(caller_context as *const tokio::sync::Notify);
                    n.notify_one();
                }
            }

            let raw_ptr = std::sync::Arc::into_raw(notify);
            let mut handle = HANDLE::default();
            let status = unsafe {
                NotifyIpInterfaceChange(
                    AF_UNSPEC,
                    Some(callback),
                    Some(raw_ptr as *const std::ffi::c_void),
                    BOOLEAN(0),
                    &mut handle,
                )
            };
            if status.0 == 0 {
                Some(Self {
                    handle,
                    notify_ptr: raw_ptr,
                })
            } else {
                unsafe {
                    drop(std::sync::Arc::from_raw(raw_ptr));
                }
                warn!("NotifyIpInterfaceChange registration failed: {}", status.0);
                None
            }
        }
    }

    impl Drop for IpChangeSubscription {
        fn drop(&mut self) {
            unsafe {
                let _ = CancelMibChangeNotify2(self.handle);
                drop(std::sync::Arc::from_raw(self.notify_ptr));
            }
        }
    }

    /// Dynamic WFP permit filters shared by every running process of the same executable.
    /// `ALE_APP_ID` filters apply per executable path, so one filter set per exe avoids
    /// duplicate filters and repeated ALE reauthorization when apps spawn many processes.
    struct ExeGroup {
        exe_path: String,
        network: NetworkPolicy,
        ips: Option<Vec<IpAddr>>,
        filter_ids: Vec<u64>,
    }

    struct DesiredGroup {
        exe_path: String,
        network: NetworkPolicy,
        ips: Option<Vec<IpAddr>>,
    }

    struct LoopState {
        groups: HashMap<String, ExeGroup>,
        learned_paths: HashSet<String>,
        ncsi_filter_ids: Vec<u64>,
        ncsi_ips: Option<Vec<IpAddr>>,
        locks: ImageLockTable,
        locked_pids: HashSet<u32>,
        last_event_poll: DateTime<Utc>,
    }

    /// Coordinates persistent WFP default-deny filters, adapter DNS redirection,
    /// NTFS `FILE_SHARE_READ`-only image locking, and dynamic per-executable WFP
    /// permit filters as processes start and exit, rules change, or DNS answers arrive.
    pub async fn run_windows_enforcement_loop(
        engine: ServiceEngine,
        data_dir: PathBuf,
        fallback_upstream: SocketAddr,
        mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) {
        // If Curb starts while not enforcing (e.g. after a crash while enforcing and a
        // later emergency-disable), make sure no stale default-deny filters or loopback
        // DNS settings are left behind that could strand the machine offline.
        let starts_enforcing = {
            let guard = engine.state.lock().unwrap();
            guard.config.mode.is_actively_enforcing(Utc::now())
        };
        if !starts_enforcing {
            let dir = data_dir.clone();
            let _ = tokio::task::spawn_blocking(move || {
                let _ = curb_core::cleanup::purge_all_curb_wfp_objects();
                if curb_core::store::dns_backup_path(&dir).exists() {
                    let _ = restore_original_adapter_dns(&dir);
                }
            })
            .await;
        }

        // Retry opening WFP with backoff in case Windows Base Filtering Engine (BFE) is
        // still starting at boot, honoring shutdown requests cleanly.
        let mut wfp = loop {
            match WfpController::open() {
                Ok(ctrl) => break ctrl,
                Err(e) => {
                    warn!("Could not open WFP engine yet ({e}); retrying in 2s");
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_secs(2)) => {}
                        _ = shutdown_rx.changed() => {
                            if *shutdown_rx.borrow() {
                                return;
                            }
                        }
                    }
                    if *shutdown_rx.borrow() {
                        return;
                    }
                }
            }
        };

        let _ip_change_sub = IpChangeSubscription::register(engine.dns_refresh_notify.clone());

        let service_exe = std::env::current_exe().ok();
        let mut st = LoopState {
            groups: HashMap::new(),
            learned_paths: HashSet::new(),
            ncsi_filter_ids: Vec::new(),
            ncsi_ips: None,
            locks: ImageLockTable::default(),
            locked_pids: HashSet::new(),
            last_event_poll: Utc::now(),
        };

        let mut was_enforcing = false;
        let mut last_baseline = None;
        let mut last_config_version: Option<u64> = None;
        let mut last_dns_version: u64 = 0;
        let mut dns_redirected = false;
        let mut last_dns_attempt: Option<Instant> = None;
        let mut last_ncsi_prewarm: Option<Instant> = None;

        let notify = engine.reconcile_notify.clone();
        let dns_refresh = engine.dns_refresh_notify.clone();
        let mut ticker = tokio::time::interval(Duration::from_millis(300));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            let mut woke_by_notify = false;
            let mut woke_by_net_change = false;
            tokio::select! {
                _ = ticker.tick() => {}
                _ = notify.notified() => {
                    woke_by_notify = true;
                }
                _ = dns_refresh.notified() => {
                    woke_by_net_change = true;
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
            }
            if *shutdown_rx.borrow() {
                break;
            }

            let (enforcing, baseline, config_version, dns_version) = {
                let mut guard = engine.state.lock().unwrap();
                guard.dns_cache.prune_expired();
                (
                    guard.config.mode.is_actively_enforcing(Utc::now()),
                    guard.config.baseline.clone(),
                    guard.config_version,
                    guard.dns_cache.version(),
                )
            };

            // Handle transitions between Enforcing and Paused/Disabled (or baseline changes).
            if enforcing && (!was_enforcing || last_baseline.as_ref() != Some(&baseline)) {
                let svc = service_exe.clone();
                let res = tokio::task::block_in_place(|| {
                    wfp.install_default_deny_and_baseline(&baseline, svc.as_deref())
                });
                if let Err(e) = res {
                    warn!("Failed to apply WFP default-deny baseline: {e}");
                }
                if !was_enforcing {
                    last_config_version = None;
                    st.last_event_poll = Utc::now();
                }
                st.ncsi_ips = None; // force NCSI permit refresh
                was_enforcing = true;
                engine.set_wfp_loop_active(true);
                last_baseline = Some(baseline.clone());
            } else if !enforcing && was_enforcing {
                engine.set_wfp_loop_active(false);
                tokio::task::block_in_place(|| {
                    release_everything(&engine, &mut wfp, &mut st);
                    wfp.clear_persistent_filters();
                    if let Err(e) = restore_original_adapter_dns(&data_dir) {
                        warn!("Failed to restore adapter DNS: {e}");
                    }
                });
                engine.set_upstream_dns(Vec::new());
                dns_redirected = false;
                last_dns_attempt = None;
                last_ncsi_prewarm = None;
                last_config_version = None;
                was_enforcing = false;
                continue;
            }

            if !enforcing {
                continue;
            }

            let config_changed = last_config_version != Some(config_version);

            // Fast path: when woken up by a new DNS resolution while rules are unchanged,
            // immediately update DNS-scoped WFP permit filters (e.g. steamwebhelper.exe &
            // NCSI) and signal the DNS proxy BEFORE returning the DNS reply to the app.
            // This avoids the race where Chromium receives an IP and connects before WFP
            // permits it (causing immediate WSAEACCES page load failures).
            if woke_by_notify && !config_changed && dns_version != last_dns_version {
                tokio::task::block_in_place(|| {
                    sync_dns_scoped_filters(&engine, &wfp, &mut st);
                });
                last_dns_version = dns_version;
                engine.mark_wfp_dns_applied(dns_version);
                continue;
            }

            // Point active interfaces at Curb's DNS proxy once it is listening, reacting
            // immediately on network/VPN/sleep events (debounced) and periodically as a
            // safety net.
            let due = match last_dns_attempt {
                None => true,
                Some(t) if woke_by_net_change => t.elapsed() >= DNS_EVENT_DEBOUNCE,
                Some(t) if !dns_redirected => t.elapsed() >= DNS_REDIRECT_RETRY,
                Some(t) => t.elapsed() >= DNS_REDIRECT_REFRESH,
            };
            if due && engine.is_dns_v4_ready() {
                last_dns_attempt = Some(Instant::now());
                let include_v6 = engine.is_dns_v6_ready();
                let dir = data_dir.clone();
                let res = tokio::task::spawn_blocking(move || {
                    enable_local_dns_redirect(&dir, include_v6)
                })
                .await
                .unwrap_or_else(|e| Err(e.to_string()));
                match res {
                    Ok(upstreams) => {
                        engine.set_upstream_dns(upstreams);
                        if !dns_redirected {
                            dns_redirected = true;
                        }
                    }
                    Err(e) => warn!("Failed to point adapter DNS to 127.0.0.1: {e}"),
                }
            }

            // Keep Microsoft NCSI probe IPs warm before their 600s cache TTL floor expires
            // (and immediately after network/sleep events) so Windows never flags "No Internet".
            let ncsi_refresh_due = dns_redirected
                && baseline.ncsi
                && (woke_by_net_change
                    || last_ncsi_prewarm.is_none_or(|t| t.elapsed() >= NCSI_PREWARM_REFRESH));
            if ncsi_refresh_due {
                last_ncsi_prewarm = Some(Instant::now());
                let eng = engine.clone();
                tokio::spawn(async move {
                    crate::dns_proxy::prewarm_ncsi_dns(&eng, fallback_upstream).await;
                });
            }

            last_config_version = Some(config_version);

            tokio::task::block_in_place(|| {
                reconcile(&engine, &wfp, &mut st, config_changed);
            });
            last_dns_version = dns_version;
            engine.mark_wfp_dns_applied(dns_version);
        }

        // Clean teardown when CurbService stops or shuts down so the machine is never left
        // stranded with 127.0.0.1 adapter DNS or persistent default-deny filters while the
        // service is stopped.
        engine.set_wfp_loop_active(false);
        if was_enforcing {
            info!("CurbService stopping — restoring adapter DNS and clearing WFP filters");
            tokio::task::block_in_place(|| {
                release_everything(&engine, &mut wfp, &mut st);
                wfp.clear_persistent_filters();
                if let Err(e) = restore_original_adapter_dns(&data_dir) {
                    warn!("Failed to restore adapter DNS on service stop: {e}");
                }
            });
        }
    }

    /// Fast-path WFP update for DNS-scoped app groups (e.g. `steamwebhelper.exe`) and
    /// Windows NCSI probes when a new DNS answer arrives, skipping process enumeration.
    fn sync_dns_scoped_filters(engine: &ServiceEngine, wfp: &WfpController, st: &mut LoopState) {
        let (updates, ncsi_enabled, ncsi_ips) = {
            let guard = engine.state.lock().unwrap();
            let mut updates = Vec::new();
            for (key, g) in &st.groups {
                if g.network.dns_whitelist.is_some() {
                    let new_ips = guard.allowed_ips_for_network(&g.network);
                    if g.ips != new_ips {
                        updates.push((key.clone(), new_ips));
                    }
                }
            }
            (
                updates,
                guard.config.baseline.ncsi,
                guard.ncsi_allowed_ips(),
            )
        };

        for (key, new_ips) in updates {
            if let Some(g) = st.groups.get_mut(&key) {
                match wfp.replace_app_dynamic(
                    &g.filter_ids,
                    Path::new(&g.exe_path),
                    &g.network,
                    new_ips.as_deref(),
                    None,
                ) {
                    Ok(ids) => {
                        g.ips = new_ips;
                        g.filter_ids = ids;
                    }
                    Err(e) => warn!("Failed fast-path WFP DNS update for {}: {e}", g.exe_path),
                }
            }
        }

        update_ncsi_filters(wfp, st, ncsi_enabled, ncsi_ips);
    }

    /// Updates dynamic WFP permit filters for Windows NCSI (`svchost.exe` / `NlaSvc`)
    /// on TCP 80 and TCP 443 to resolved Microsoft connectivity-check IPs.
    /// While `ncsi_enabled` is true, keeps existing NCSI permit filters pinned if the
    /// cache momentarily empties between refreshes rather than tearing them down.
    fn update_ncsi_filters(
        wfp: &WfpController,
        st: &mut LoopState,
        ncsi_enabled: bool,
        ncsi_ips: Vec<IpAddr>,
    ) {
        let should_update = if !ncsi_enabled {
            !st.ncsi_filter_ids.is_empty() || st.ncsi_ips.as_ref().is_some_and(|v| !v.is_empty())
        } else {
            !ncsi_ips.is_empty() && st.ncsi_ips.as_ref() != Some(&ncsi_ips)
        };
        if !should_update {
            return;
        }

        let svchost = system32_path("svchost.exe");
        let res = if !ncsi_enabled {
            wfp.remove_dynamic_filters(&st.ncsi_filter_ids);
            Ok(Vec::new())
        } else {
            wfp.replace_app_dynamic_ports(
                &st.ncsi_filter_ids,
                &svchost,
                &NetworkPolicy {
                    allow_tcp: true,
                    allow_udp: false,
                    dns_whitelist: None,
                },
                Some(&ncsi_ips),
                &[80, 443],
            )
        };
        match res {
            Ok(ids) => {
                st.ncsi_filter_ids = ids;
                st.ncsi_ips = Some(if ncsi_enabled { ncsi_ips } else { Vec::new() });
            }
            Err(e) => warn!("Failed to apply NCSI connectivity-check WFP filters: {e}"),
        }
    }

    /// Desired-state reconciliation: evaluates live processes, computes one WFP filter
    /// set per allowed executable, and atomically applies only the differences.
    fn reconcile(
        engine: &ServiceEngine,
        wfp: &WfpController,
        st: &mut LoopState,
        config_changed: bool,
    ) {
        let live = snapshot_live_processes();

        // Start from previously tracked processes that are still alive (unless rules
        // changed, in which case every process is re-evaluated against the new rules).
        let prev_tracked = {
            let mut guard = engine.state.lock().unwrap();
            std::mem::take(&mut guard.tracked_processes)
        };

        let mut pending: Vec<(u32, u32, String)> = Vec::new();
        {
            let mut guard = engine.state.lock().unwrap();
            for (pid, ppid, path) in &live {
                if !config_changed {
                    if let Some(t) = prev_tracked.get(pid) {
                        if t.identity.path.eq_ignore_ascii_case(path) {
                            guard.tracked_processes.insert(*pid, t.clone());
                            continue;
                        }
                    }
                }
                pending.push((*pid, *ppid, path.clone()));
            }
        }

        // Evaluate untracked processes. Multiple passes let helper processes inherit
        // from parents that are matched later in the same snapshot. Acquire the NTFS
        // `FILE_SHARE_READ`-only lock BEFORE `inspect_binary` to eliminate the TOCTOU
        // window between signature/hash inspection and image locking.
        let mut rules_updated = false;
        for _pass in 0..3 {
            let mut progressed = false;
            let mut remaining = Vec::new();
            for (pid, ppid, path) in pending {
                let locked_now = if !st.locked_pids.contains(&pid) {
                    st.locks.lock_for_pid(pid, Path::new(&path))
                } else {
                    false
                };
                let Ok(identity) = inspect_binary(Path::new(&path)) else {
                    if locked_now {
                        st.locks.release_pid(pid);
                    }
                    continue;
                };
                let mut guard = engine.state.lock().unwrap();
                // Backfill or refresh exe_path on user rules when a direct match is observed
                // (e.g. when a self-updating app moves to a new versioned subfolder like
                // `app-1.0.9175\Discord.exe`) so install-directory helper matching and
                // proactive 0ms WFP filters automatically follow updates.
                for rule in &mut guard.config.rules {
                    if rule.enabled
                        && rule.matcher.matches(&identity)
                        && rule
                            .exe_path
                            .as_deref()
                            .is_none_or(|p| !p.eq_ignore_ascii_case(&identity.path))
                    {
                        rule.exe_path = Some(identity.path.clone());
                        rules_updated = true;
                    }
                }
                match guard.evaluate_process(Some(ppid), &identity) {
                    Some((rule_label, network, allow_subprocesses)) => {
                        if !prev_tracked.contains_key(&pid) {
                            info!(
                                "Allowed PID {pid} ({}) via rule '{rule_label}'",
                                identity.filename
                            );
                        }
                        if locked_now {
                            st.locked_pids.insert(pid);
                        }
                        if is_admin_protected_path(&identity.path) {
                            st.learned_paths.insert(identity.path.clone());
                        }
                        guard.tracked_processes.insert(
                            pid,
                            TrackedProcess {
                                pid,
                                identity,
                                rule_label,
                                network,
                                allow_subprocesses,
                                dynamic_filter_ids: Vec::new(),
                            },
                        );
                        progressed = true;
                    }
                    None => {
                        if locked_now {
                            st.locks.release_pid(pid);
                        }
                        remaining.push((pid, ppid, path));
                    }
                }
            }
            pending = remaining;
            if !progressed || pending.is_empty() {
                break;
            }
        }

        if rules_updated {
            let guard = engine.state.lock().unwrap();
            let _ = save_config(&guard.data_dir, &guard.config);
        }

        // Gather proactive candidate paths ONLY in admin-protected directories
        // (`Program Files`, `Program Files (x86)`, `Windows`) so allowed system/installed
        // apps keep 0ms WFP startup filters while user-writable directories (`%LOCALAPPDATA%`,
        // Steam game libraries) cannot be exploited via closed-binary rename-and-swap.
        let candidate_paths = {
            let guard = engine.state.lock().unwrap();
            let mut paths = Vec::new();
            for p in guard.candidate_rule_paths() {
                if is_admin_protected_path(&p)
                    && !paths.iter().any(|x: &String| x.eq_ignore_ascii_case(&p))
                {
                    paths.push(p);
                }
            }
            for p in &st.learned_paths {
                if is_admin_protected_path(p)
                    && !paths.iter().any(|x| x.eq_ignore_ascii_case(p))
                {
                    paths.push(p.clone());
                }
            }
            paths
        };

        let mut verified_proactive: Vec<(BinaryIdentity, NetworkPolicy)> = Vec::new();
        let mut active_learned = HashSet::new();
        for path in candidate_paths {
            let Ok(identity) = inspect_binary(Path::new(&path)) else {
                continue;
            };
            let verdict = {
                let guard = engine.state.lock().unwrap();
                guard.evaluate_process(None, &identity)
            };
            if let Some((_label, network, _sub)) = verdict {
                active_learned.insert(identity.path.clone());
                verified_proactive.push((identity, network));
            }
        }
        st.learned_paths = active_learned;

        // Compute desired per-executable groups and NCSI permit IPs.
        let (desired, tracked_pids, ncsi_enabled, ncsi_ips) = {
            let guard = engine.state.lock().unwrap();
            let mut pids: Vec<&u32> = guard.tracked_processes.keys().collect();
            pids.sort();
            let mut desired: HashMap<String, DesiredGroup> = HashMap::new();
            for pid in pids {
                let t = &guard.tracked_processes[pid];
                let key = t.identity.path.to_ascii_lowercase();
                desired.entry(key).or_insert_with(|| DesiredGroup {
                    exe_path: t.identity.path.clone(),
                    network: t.network.clone(),
                    ips: guard.allowed_ips_for_network(&t.network),
                });
            }
            for (identity, network) in verified_proactive {
                let key = identity.path.to_ascii_lowercase();
                desired.entry(key).or_insert_with(|| DesiredGroup {
                    exe_path: identity.path,
                    ips: guard.allowed_ips_for_network(&network),
                    network,
                });
            }
            let tracked: HashSet<u32> = guard.tracked_processes.keys().copied().collect();
            (
                desired,
                tracked,
                guard.config.baseline.ncsi,
                guard.ncsi_allowed_ips(),
            )
        };

        // Ensure every tracked running PID holds an NTFS image lock, and release exited PIDs.
        for pid in &tracked_pids {
            if !st.locked_pids.contains(pid) {
                let path = {
                    let guard = engine.state.lock().unwrap();
                    guard.tracked_processes.get(pid).map(|t| t.identity.path.clone())
                };
                if let Some(p) = path {
                    if st.locks.lock_for_pid(*pid, Path::new(&p)) {
                        st.locked_pids.insert(*pid);
                    }
                }
            }
        }
        let stale_locks: Vec<u32> = st
            .locked_pids
            .iter()
            .filter(|p| !tracked_pids.contains(p))
            .copied()
            .collect();
        for pid in stale_locks {
            st.locks.release_pid(pid);
            st.locked_pids.remove(&pid);
        }

        // Remove groups that are no longer desired.
        let obsolete: Vec<String> = st
            .groups
            .keys()
            .filter(|k| !desired.contains_key(*k))
            .cloned()
            .collect();
        for key in obsolete {
            if let Some(g) = st.groups.remove(&key) {
                wfp.remove_dynamic_filters(&g.filter_ids);
            }
        }

        // Add or atomically update groups whose policy or resolved IPs changed.
        for (key, d) in desired {
            let unchanged = st
                .groups
                .get(&key)
                .is_some_and(|g| g.network == d.network && g.ips == d.ips);
            if unchanged {
                continue;
            }
            let old_ids = st
                .groups
                .get(&key)
                .map(|g| g.filter_ids.clone())
                .unwrap_or_default();
            match wfp.replace_app_dynamic(
                &old_ids,
                Path::new(&d.exe_path),
                &d.network,
                d.ips.as_deref(),
                None,
            ) {
                Ok(ids) => {
                    st.groups.insert(
                        key,
                        ExeGroup {
                            exe_path: d.exe_path,
                            network: d.network,
                            ips: d.ips,
                            filter_ids: ids,
                        },
                    );
                }
                Err(e) => warn!("Failed to apply dynamic WFP filters for {}: {e}", d.exe_path),
            }
        }

        // Windows NCSI: allow the Network List Service (svchost.exe) to reach the
        // resolved Microsoft connectivity-check hosts on TCP 80 & 443 so Windows does not
        // flag Wi-Fi as "No Internet" and bounce the connection.
        update_ncsi_filters(wfp, st, ncsi_enabled, ncsi_ips);

        // Poll recent WFP classify-drop events so blocked apps appear in the UI's
        // "Recently blocked" feed and Running Apps picker with their real exe path.
        let now_utc = Utc::now();
        if (now_utc - st.last_event_poll).num_milliseconds() >= 900 {
            let start_ft = datetime_to_filetime(st.last_event_poll);
            let end_ft = datetime_to_filetime(now_utc);
            st.last_event_poll = now_utc;

            let drops = wfp.poll_classify_drops(start_ft, end_ft);
            for (win32_path, remote_ip, remote_port) in drops {
                // Skip LAN multicast discovery noise (e.g. SSDP 239.255.255.250:1900, mDNS
                // 224.0.0.251:5353) from the UI feed; WFP still blocks it cleanly.
                if remote_ip.is_multicast() {
                    continue;
                }
                let key = win32_path.to_ascii_lowercase();
                // Skip if the app is already in an unrestricted allowed group.
                if st
                    .groups
                    .get(&key)
                    .is_some_and(|g| g.ips.is_none())
                {
                    continue;
                }
                let filename = Path::new(&win32_path)
                    .file_name()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| win32_path.clone());
                if filename.eq_ignore_ascii_case("svchost.exe")
                    || filename.eq_ignore_ascii_case("curb-service.exe")
                {
                    continue;
                }

                let peeked = peek_binary(Path::new(&win32_path)).ok();
                let signed = peeked
                    .as_ref()
                    .and_then(|i| i.signature.as_ref())
                    .is_some();
                let app_name = peeked
                    .as_ref()
                    .and_then(|i| i.product_name.clone())
                    .unwrap_or_else(|| {
                        filename
                            .strip_suffix(".exe")
                            .or_else(|| filename.strip_suffix(".EXE"))
                            .unwrap_or(&filename)
                            .to_string()
                    });
                let signer = peeked
                    .and_then(|i| i.signature)
                    .map(|s| s.subject_cn);

                let mut guard = engine.state.lock().unwrap();
                let destination = guard
                    .dns_cache
                    .domain_for_ip(remote_ip)
                    .unwrap_or_else(|| format!("{remote_ip}:{remote_port}"));
                let is_steam_community = destination
                    .to_ascii_lowercase()
                    .contains("steamcommunity.com");
                guard.record_blocked_event(BlockedEvent {
                    id: Uuid::new_v4(),
                    timestamp: now_utc,
                    app_name: if is_steam_community {
                        "Steam Community".into()
                    } else {
                        app_name
                    },
                    exe: filename,
                    path: win32_path,
                    destination,
                    signed,
                    signer,
                    is_steam_community,
                });
            }
        }

        // Update active filter count for UI status reporting.
        let total: usize = st.groups.values().map(|g| g.filter_ids.len()).sum::<usize>()
            + st.ncsi_filter_ids.len();
        let mut guard = engine.state.lock().unwrap();
        guard.active_wfp_filters = total;
        let _ = st.groups.values().map(|g| &g.exe_path).count();
    }

    fn release_everything(engine: &ServiceEngine, wfp: &mut WfpController, st: &mut LoopState) {
        for (_, g) in st.groups.drain() {
            wfp.remove_dynamic_filters(&g.filter_ids);
        }
        st.learned_paths.clear();
        wfp.remove_dynamic_filters(&st.ncsi_filter_ids);
        st.ncsi_filter_ids.clear();
        st.ncsi_ips = None;
        for pid in st.locked_pids.drain() {
            st.locks.release_pid(pid);
        }
        let mut guard = engine.state.lock().unwrap();
        guard.tracked_processes.clear();
        guard.active_wfp_filters = 0;
    }

    fn system32_path(exe: &str) -> PathBuf {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        PathBuf::from(root).join("System32").join(exe)
    }

    /// Converts a `DateTime<Utc>` to a Windows `FILETIME` (100-ns intervals since 1601-01-01).
    fn datetime_to_filetime(dt: DateTime<Utc>) -> FILETIME {
        const EPOCH_DIFF_SECS: i64 = 11_644_473_600;
        let secs = dt.timestamp().saturating_add(EPOCH_DIFF_SECS).max(0) as u64;
        let nanos = dt.timestamp_subsec_nanos() as u64;
        let ticks = secs.saturating_mul(10_000_000).saturating_add(nanos / 100);
        FILETIME {
            dwLowDateTime: (ticks & 0xFFFF_FFFF) as u32,
            dwHighDateTime: (ticks >> 32) as u32,
        }
    }

    fn snapshot_live_processes() -> Vec<(u32, u32, String)> {
        let mut out = Vec::new();
        unsafe {
            let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
                return out;
            };
            let mut entry = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };
            if Process32FirstW(snap, &mut entry).is_ok() {
                loop {
                    let pid = entry.th32ProcessID;
                    let ppid = entry.th32ParentProcessID;
                    if let Some(path) = query_path(pid) {
                        out.push((pid, ppid, path));
                    }
                    if Process32NextW(snap, &mut entry).is_err() {
                        break;
                    }
                }
            }
            let _ = CloseHandle(snap);
        }
        out
    }

    unsafe fn query_path(pid: u32) -> Option<String> {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_FORMAT(0),
            PWSTR(buf.as_mut_ptr()),
            &mut len,
        );
        let _ = CloseHandle(handle);
        if ok.is_ok() && len > 0 {
            Some(String::from_utf16_lossy(&buf[..len as usize]))
        } else {
            None
        }
    }

    /// Returns true if `path` resides under a standard Windows admin-writable-only
    /// directory (`Program Files`, `Program Files (x86)`, or `Windows`), where a
    /// non-admin user cannot rename-and-swap a closed executable.
    fn is_admin_protected_path(path: &str) -> bool {
        let norm = path.replace('/', "\\").to_ascii_lowercase();
        let roots = [
            std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".into()),
            std::env::var("ProgramFiles(x86)")
                .unwrap_or_else(|_| r"C:\Program Files (x86)".into()),
            std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()),
        ];
        roots.iter().any(|root| {
            let mut prefix = root
                .replace('/', "\\")
                .trim_end_matches('\\')
                .to_ascii_lowercase();
            prefix.push('\\');
            norm.starts_with(&prefix)
        })
    }
}
