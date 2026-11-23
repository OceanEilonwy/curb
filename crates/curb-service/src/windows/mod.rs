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
    use std::time::{Duration, Instant, SystemTime};

    use chrono::Utc;
    use curb_core::config::NetworkPolicy;
    use curb_core::verify::{inspect_binary, BinaryIdentity};
    use tracing::{info, warn};
    use windows::core::PWSTR;
    use windows::Win32::Foundation::CloseHandle;
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

    /// How often to re-apply adapter DNS redirection so newly connected / reconnected
    /// adapters (e.g. Wi-Fi roaming) keep resolving through Curb instead of losing DNS.
    const DNS_REDIRECT_REFRESH: Duration = Duration::from_secs(60);
    /// Back-off before retrying a failed adapter DNS redirect.
    const DNS_REDIRECT_RETRY: Duration = Duration::from_secs(15);

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
        ncsi_filter_ids: Vec<u64>,
        ncsi_ips: Option<Vec<IpAddr>>,
        locks: ImageLockTable,
        locked_pids: HashSet<u32>,
        verify_cache: HashMap<(String, u64, SystemTime), BinaryIdentity>,
    }

    /// Coordinates persistent WFP default-deny filters, adapter DNS redirection,
    /// NTFS `FILE_SHARE_READ`-only image locking, and dynamic per-executable WFP
    /// permit filters as processes start and exit, rules change, or DNS answers arrive.
    pub async fn run_windows_enforcement_loop(
        engine: ServiceEngine,
        data_dir: PathBuf,
        fallback_upstream: SocketAddr,
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

        let mut wfp = match WfpController::open() {
            Ok(ctrl) => ctrl,
            Err(e) => {
                warn!("Could not open WFP engine (run as SYSTEM/Administrator): {e}");
                return;
            }
        };

        let service_exe = std::env::current_exe().ok();
        let mut st = LoopState {
            groups: HashMap::new(),
            ncsi_filter_ids: Vec::new(),
            ncsi_ips: None,
            locks: ImageLockTable::default(),
            locked_pids: HashSet::new(),
            verify_cache: HashMap::new(),
        };

        let mut was_enforcing = false;
        let mut last_baseline = None;
        let mut last_config_version: Option<u64> = None;
        let mut dns_redirected = false;
        let mut last_dns_attempt: Option<Instant> = None;

        let notify = engine.reconcile_notify.clone();
        let mut ticker = tokio::time::interval(Duration::from_millis(1000));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = ticker.tick() => {}
                _ = notify.notified() => {}
            }

            let (enforcing, baseline, config_version) = {
                let mut guard = engine.state.lock().unwrap();
                guard.dns_cache.prune_expired();
                (
                    guard.config.mode.is_actively_enforcing(Utc::now()),
                    guard.config.baseline.clone(),
                    guard.config_version,
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
                }
                st.ncsi_ips = None; // force NCSI permit refresh
                was_enforcing = true;
                last_baseline = Some(baseline);
            } else if !enforcing && was_enforcing {
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
                last_config_version = None;
                was_enforcing = false;
                continue;
            }

            if !enforcing {
                continue;
            }

            // Point adapters at Curb's DNS proxy only once it is actually listening, and
            // periodically re-apply so reconnected Wi-Fi adapters keep working DNS.
            let due = match last_dns_attempt {
                None => true,
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
                            let eng = engine.clone();
                            tokio::spawn(async move {
                                crate::dns_proxy::prewarm_ncsi_dns(&eng, fallback_upstream).await;
                            });
                        }
                    }
                    Err(e) => warn!("Failed to point adapter DNS to 127.0.0.1: {e}"),
                }
            }

            let config_changed = last_config_version != Some(config_version);
            last_config_version = Some(config_version);

            tokio::task::block_in_place(|| {
                reconcile(&engine, &wfp, &mut st, config_changed);
            });
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
        // from parents that are matched later in the same snapshot.
        for _pass in 0..3 {
            let mut progressed = false;
            let mut remaining = Vec::new();
            for (pid, ppid, path) in pending {
                let Some(identity) = inspect_cached(&path, &mut st.verify_cache) else {
                    continue;
                };
                let mut guard = engine.state.lock().unwrap();
                match guard.evaluate_process(Some(ppid), &identity) {
                    Some((rule_label, network, allow_subprocesses)) => {
                        if !prev_tracked.contains_key(&pid) {
                            info!(
                                "Allowed PID {pid} ({}) via rule '{rule_label}'",
                                identity.filename
                            );
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
                    None => remaining.push((pid, ppid, path)),
                }
            }
            pending = remaining;
            if !progressed || pending.is_empty() {
                break;
            }
        }

        // Compute desired per-executable groups and NCSI permit IPs.
        let (desired, tracked_pids, ncsi_ips) = {
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
            let tracked: HashSet<u32> = guard.tracked_processes.keys().copied().collect();
            (desired, tracked, guard.ncsi_allowed_ips())
        };

        // Image locks: lock newly allowed processes, release ones no longer allowed.
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
        // resolved Microsoft connectivity-check hosts on TCP 80 so Windows does not
        // flag Wi-Fi as "No Internet" and bounce the connection.
        if st.ncsi_ips.as_ref() != Some(&ncsi_ips) {
            let svchost = system32_path("svchost.exe");
            let res = if ncsi_ips.is_empty() {
                wfp.remove_dynamic_filters(&st.ncsi_filter_ids);
                Ok(Vec::new())
            } else {
                wfp.replace_app_dynamic(
                    &st.ncsi_filter_ids,
                    &svchost,
                    &NetworkPolicy {
                        allow_tcp: true,
                        allow_udp: false,
                        dns_whitelist: None,
                    },
                    Some(&ncsi_ips),
                    Some(80),
                )
            };
            match res {
                Ok(ids) => {
                    st.ncsi_filter_ids = ids;
                    st.ncsi_ips = Some(ncsi_ips);
                }
                Err(e) => warn!("Failed to apply NCSI connectivity-check WFP filters: {e}"),
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

    fn inspect_cached(
        path: &str,
        cache: &mut HashMap<(String, u64, SystemTime), BinaryIdentity>,
    ) -> Option<BinaryIdentity> {
        let meta = std::fs::metadata(path).ok()?;
        let modified = meta.modified().ok()?;
        let key = (path.to_ascii_lowercase(), meta.len(), modified);
        if let Some(existing) = cache.get(&key) {
            return Some(existing.clone());
        }
        let identity = inspect_binary(Path::new(path)).ok()?;
        cache.insert(key, identity.clone());
        Some(identity)
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
}
