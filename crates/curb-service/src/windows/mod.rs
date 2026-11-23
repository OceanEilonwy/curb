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
    use std::path::{Path, PathBuf};
    use std::time::{Duration, SystemTime};

    use chrono::Utc;
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

    /// Coordinates persistent WFP default-deny filters, adapter DNS redirection,
    /// NTFS `FILE_SHARE_READ`-only image locking, and dynamic per-process WFP
    /// permit filters as processes start and exit or configuration changes.
    pub async fn run_windows_enforcement_loop(engine: ServiceEngine, data_dir: PathBuf) {
        let mut wfp = match WfpController::open() {
            Ok(ctrl) => ctrl,
            Err(e) => {
                warn!("Could not open WFP engine (run as SYSTEM/Administrator): {e}");
                return;
            }
        };

        let service_exe = std::env::current_exe().ok();
        let mut locks = ImageLockTable::default();
        let mut verify_cache: HashMap<(String, u64, SystemTime), BinaryIdentity> = HashMap::new();
        let mut was_enforcing = false;
        let mut last_baseline = None;

        let mut ticker = tokio::time::interval(Duration::from_millis(500));

        loop {
            ticker.tick().await;

            let (enforcing, baseline) = {
                let guard = engine.state.lock().unwrap();
                (
                    guard.config.mode.is_actively_enforcing(Utc::now()),
                    guard.config.baseline.clone(),
                )
            };

            // Handle transitions between Enforcing and Paused/Disabled (or baseline changes).
            if enforcing && (!was_enforcing || last_baseline.as_ref() != Some(&baseline)) {
                if let Err(e) =
                    wfp.install_default_deny_and_baseline(&baseline, service_exe.as_deref())
                {
                    warn!("Failed to apply WFP default-deny baseline: {e}");
                }
                if let Err(e) = enable_local_dns_redirect(&data_dir) {
                    warn!("Failed to point adapter DNS to 127.0.0.1: {e}");
                }
                was_enforcing = true;
                last_baseline = Some(baseline);
            } else if !enforcing && was_enforcing {
                // Release all active dynamic filters, locks, default-deny, and restore DNS.
                let old_pids: Vec<u32> = {
                    let mut guard = engine.state.lock().unwrap();
                    let pids: Vec<u32> = guard.tracked_processes.keys().copied().collect();
                    for proc in guard.tracked_processes.values() {
                        wfp.remove_dynamic_filters(&proc.dynamic_filter_ids);
                    }
                    guard.tracked_processes.clear();
                    guard.active_wfp_filters = 0;
                    pids
                };
                for pid in old_pids {
                    locks.release_pid(pid);
                }
                wfp.clear_persistent_filters();
                if let Err(e) = restore_original_adapter_dns(&data_dir) {
                    warn!("Failed to restore adapter DNS: {e}");
                }
                was_enforcing = false;
                continue;
            }

            if !enforcing {
                continue;
            }

            // Reconcile currently running processes against active rules & DNS cache.
            let live = snapshot_live_processes();
            let live_pids: HashSet<u32> = live.iter().map(|(pid, _, _)| *pid).collect();

            // 1. Clean up exited processes (remove dynamic WFP rules + release NTFS lock).
            let exited: Vec<(u32, Vec<u64>)> = {
                let mut guard = engine.state.lock().unwrap();
                let mut gone = Vec::new();
                guard.tracked_processes.retain(|pid, proc| {
                    if live_pids.contains(pid) {
                        true
                    } else {
                        gone.push((*pid, proc.dynamic_filter_ids.clone()));
                        false
                    }
                });
                gone
            };
            for (pid, filter_ids) in exited {
                wfp.remove_dynamic_filters(&filter_ids);
                locks.release_pid(pid);
            }

            // 2. Inspect newly observed processes.
            for (pid, ppid, exe_path) in live {
                let already_tracked = {
                    let guard = engine.state.lock().unwrap();
                    guard.tracked_processes.contains_key(&pid)
                };
                if already_tracked {
                    continue;
                }

                let Some(identity) = inspect_cached(&exe_path, &mut verify_cache) else {
                    continue;
                };

                let verdict = {
                    let guard = engine.state.lock().unwrap();
                    guard
                        .evaluate_process(Some(ppid), &identity)
                        .map(|(label, net, sub)| {
                            let ips = guard.allowed_ips_for_network(&net);
                            (label, net, sub, ips)
                        })
                };

                if let Some((rule_label, network, allow_subprocesses, allowed_ips)) = verdict {
                    let path_obj = Path::new(&exe_path);
                    let _ = locks.lock_for_pid(pid, path_obj);
                    match wfp.permit_app_dynamic(
                        path_obj,
                        &network,
                        allowed_ips.as_deref(),
                        None,
                    ) {
                        Ok(dynamic_filter_ids) => {
                            info!(
                                "Allowed PID {pid} ({}) via rule '{rule_label}' ({} WFP filters)",
                                identity.filename,
                                dynamic_filter_ids.len()
                            );
                            let mut guard = engine.state.lock().unwrap();
                            guard.tracked_processes.insert(
                                pid,
                                TrackedProcess {
                                    pid,
                                    identity,
                                    rule_label,
                                    network,
                                    allow_subprocesses,
                                    dynamic_filter_ids,
                                },
                            );
                        }
                        Err(e) => {
                            locks.release_pid(pid);
                            warn!("Failed to add dynamic WFP filter for {exe_path}: {e}");
                        }
                    }
                }
            }

            // Update active filter count for UI status reporting.
            let mut guard = engine.state.lock().unwrap();
            guard.active_wfp_filters = guard
                .tracked_processes
                .values()
                .map(|p| p.dynamic_filter_ids.len())
                .sum();
        }
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
