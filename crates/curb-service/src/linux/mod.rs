#[cfg(target_os = "linux")]
pub async fn run_linux_enforcement_loop(
    engine: crate::engine::ServiceEngine,
    dns_proxy_port: u16,
    fallback_upstream: std::net::SocketAddr,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use chrono::Utc;
    use curb_core::adaptors::{DnsManager, FirewallManager};
    use curb_linux::dns::flush_linux_dns_caches;
    use curb_linux::proc_net::pid_exists;
    use curb_linux::{LinuxDnsManager, CURB_FW_MARK};
    use curb_nftables::{
        policy_mark_for_generation, run_nfqueue_loop_with_ready, NftablesFirewall, PacketContext,
        RulesetOptions, CURB_NFQUEUE_NUM,
    };
    use tracing::{info, warn};

    const DNS_UPSTREAM_REFRESH: Duration = Duration::from_secs(30);
    const NFT_DRIFT_CHECK: Duration = Duration::from_secs(10);
    const CONNECTIVITY_PREWARM_REFRESH: Duration = Duration::from_secs(240);

    let is_root = unsafe { libc::geteuid() == 0 };
    if !is_root {
        warn!("curb-service is running without root/CAP_NET_ADMIN; Linux nftables/NFQUEUE enforcement disabled (dev mode)");
        let _ = shutdown.changed().await;
        return;
    }

    let dns_mgr = LinuxDnsManager;
    let firewall = NftablesFirewall;

    // If Curb starts while not enforcing (e.g. after a crash/SIGKILL while enforcing
    // followed by emergency-disable or pause), purge any stale `table inet curb` so the
    // machine is never stranded offline.
    let starts_enforcing = {
        let guard = engine.state.lock().unwrap();
        guard.config.mode.is_actively_enforcing(Utc::now())
    };
    if !starts_enforcing {
        let _ = tokio::task::spawn_blocking(move || firewall.purge_all()).await;
    }

    let refresh_upstreams = |eng: &crate::engine::ServiceEngine| {
        let mut upstreams = dns_mgr.discover_upstreams();
        if !upstreams.contains(&fallback_upstream) {
            upstreams.push(fallback_upstream);
        }
        eng.set_upstream_dns(upstreams);
    };
    refresh_upstreams(&engine);

    let mut nfqueue_stop: Option<Arc<AtomicBool>> = None;
    let mut nfqueue_ready = Arc::new(AtomicBool::new(false));
    let mut nfqueue_handle: Option<std::thread::JoinHandle<()>> = None;
    let mut currently_enforcing = false;
    let mut last_baseline = None;
    let mut last_config_version: Option<u64> = None;
    let mut last_redirect_ipv6: Option<bool> = None;
    let mut policy_generation: u64 = 0;
    let current_policy_mark = Arc::new(AtomicU32::new(policy_mark_for_generation(0)));

    let mut last_upstream_refresh = Instant::now();
    let mut last_drift_check = Instant::now();
    let mut last_connectivity_prewarm: Option<Instant> = None;
    let mut logged_dns_wait = false;

    let mut tick = tokio::time::interval(Duration::from_secs(2));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        let mut woke_by_dns_refresh = false;
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    info!("Linux enforcement loop shutting down — cleaning up nftables");
                    break;
                }
            }
            _ = engine.reconcile_notify.notified() => {}
            _ = engine.dns_refresh_notify.notified() => {
                woke_by_dns_refresh = true;
            }
            _ = tick.tick() => {}
        }
        if *shutdown.borrow() {
            break;
        }

        // Periodically refresh upstream DNS resolvers (and on explicit refresh events)
        // so boot-before-DHCP, Wi-Fi switches, VPN connects, and resume stay working.
        if woke_by_dns_refresh || last_upstream_refresh.elapsed() >= DNS_UPSTREAM_REFRESH {
            refresh_upstreams(&engine);
            last_upstream_refresh = Instant::now();
        }

        let (should_enforce, baseline, config_version) = {
            let mut guard = engine.state.lock().unwrap();
            guard.dns_cache.prune_expired();
            guard.tracked_processes.retain(|&pid, _| pid_exists(pid));
            (
                guard.config.mode.is_actively_enforcing(Utc::now()),
                guard.config.baseline.clone(),
                guard.config_version,
            )
        };

        if should_enforce {
            // Never install nftables DNS redirect unless the local IPv4 DNS proxy is actually
            // bound and listening (prevents total DNS blackouts if port bind fails or --no-dns).
            if !engine.is_dns_v4_ready() {
                if !logged_dns_wait {
                    warn!(
                        "Waiting for local DNS proxy on 127.0.0.1:{dns_proxy_port} before enabling Linux nftables enforcement"
                    );
                    logged_dns_wait = true;
                }
                continue;
            }
            logged_dns_wait = false;

            // Watchdog: if the NFQUEUE thread exited unexpectedly, purge nftables immediately
            // so traffic is never blackholed, then respawn it cleanly.
            if let Some(ref handle) = nfqueue_handle {
                if handle.is_finished() {
                    warn!("Curb NFQUEUE thread exited unexpectedly; purging nftables before respawn");
                    if currently_enforcing {
                        let _ = firewall.purge_all();
                        currently_enforcing = false;
                        engine.state.lock().unwrap().active_wfp_filters = 0;
                    }
                    if let Some(h) = nfqueue_handle.take() {
                        let _ = h.join();
                    }
                    nfqueue_stop = None;
                    nfqueue_ready.store(false, Ordering::Release);
                }
            }

            if nfqueue_handle.is_none() {
                let stop_flag = Arc::new(AtomicBool::new(false));
                let ready_flag = Arc::new(AtomicBool::new(false));
                let stop_clone = stop_flag.clone();
                let ready_clone = ready_flag.clone();
                let eng = engine.clone();
                let mark_arc = current_policy_mark.clone();

                match std::thread::Builder::new()
                    .name("curb-nfqueue".into())
                    .spawn(move || {
                        let res = run_nfqueue_loop_with_ready(
                            CURB_NFQUEUE_NUM,
                            stop_clone,
                            ready_clone,
                            |ctx: &PacketContext| {
                                let policy_mark = mark_arc.load(Ordering::Acquire);
                                evaluate_linux_packet(&eng, ctx, policy_mark)
                            },
                        );
                        if let Err(e) = res {
                            warn!("Curb NFQUEUE loop exited with error: {e}");
                        }
                    }) {
                    Ok(handle) => {
                        nfqueue_stop = Some(stop_flag);
                        nfqueue_ready = ready_flag;
                        nfqueue_handle = Some(handle);
                    }
                    Err(e) => {
                        warn!("Failed to spawn NFQUEUE thread: {e}");
                        continue;
                    }
                }

                // Wait up to 2s for NFQUEUE bind ACK before installing `queue num 42`.
                for _ in 0..80 {
                    if nfqueue_ready.load(Ordering::Acquire) {
                        break;
                    }
                    if nfqueue_handle.as_ref().is_some_and(|h| h.is_finished()) {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            }

            if !nfqueue_ready.load(Ordering::Acquire) {
                warn!("NFQUEUE verifier is not bound yet; skipping nftables apply to avoid blackholing traffic");
                continue;
            }

            let redirect_ipv6 = engine.is_dns_v6_ready();
            let config_changed = last_config_version != Some(config_version);
            let baseline_changed = last_baseline.as_ref() != Some(&baseline);
            let ipv6_changed = last_redirect_ipv6 != Some(redirect_ipv6);
            let drift_detected = currently_enforcing
                && last_drift_check.elapsed() >= NFT_DRIFT_CHECK
                && {
                    last_drift_check = Instant::now();
                    !firewall.is_applied()
                };

            if drift_detected {
                warn!("Detected external flush of `table inet curb` (e.g. firewalld/ufw/nftables reload); re-applying");
            }

            if !currently_enforcing
                || config_changed
                || baseline_changed
                || ipv6_changed
                || drift_detected
            {
                let entering_enforcing = !currently_enforcing;
                if entering_enforcing || config_changed {
                    policy_generation = policy_generation.wrapping_add(1);
                    let next_mark = policy_mark_for_generation(policy_generation);
                    current_policy_mark.store(next_mark, Ordering::Release);
                    // Clear tracked_processes so disabled/deleted rules or expired playtime
                    // limits cannot leave stale subprocess inheritance behind.
                    engine.state.lock().unwrap().tracked_processes.clear();
                }

                let opts = RulesetOptions {
                    dns_proxy_port,
                    redirect_ipv6,
                    queue_num: CURB_NFQUEUE_NUM,
                    fw_mark: CURB_FW_MARK,
                    policy_ct_mark: current_policy_mark.load(Ordering::Acquire),
                };

                match firewall.apply_enforcing_with_options(&baseline, opts) {
                    Ok(()) => {
                        currently_enforcing = true;
                        last_baseline = Some(baseline.clone());
                        last_config_version = Some(config_version);
                        last_redirect_ipv6 = Some(redirect_ipv6);
                        last_drift_check = Instant::now();
                        engine.state.lock().unwrap().active_wfp_filters = 1;
                        info!(
                            "Linux nftables default-deny enforcement active (queue {CURB_NFQUEUE_NUM}, DNS redirect -> :{dns_proxy_port}, ipv6={redirect_ipv6}, gen={policy_generation})"
                        );
                        if entering_enforcing {
                            tokio::task::spawn_blocking(flush_linux_dns_caches);
                            if baseline.ncsi {
                                let eng = engine.clone();
                                tokio::spawn(async move {
                                    crate::dns_proxy::prewarm_linux_connectivity_dns(
                                        &eng,
                                        fallback_upstream,
                                    )
                                    .await;
                                });
                                last_connectivity_prewarm = Some(Instant::now());
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to apply Linux nftables ruleset: {e}");
                    }
                }
            }

            // Periodically refresh Linux connectivity-check probe IPs before TTL expiry.
            if currently_enforcing
                && baseline.ncsi
                && last_connectivity_prewarm
                    .is_none_or(|t| t.elapsed() >= CONNECTIVITY_PREWARM_REFRESH)
            {
                let eng = engine.clone();
                tokio::spawn(async move {
                    crate::dns_proxy::prewarm_linux_connectivity_dns(&eng, fallback_upstream).await;
                });
                last_connectivity_prewarm = Some(Instant::now());
            }
        } else if currently_enforcing {
            if let Err(e) = firewall.purge_all() {
                warn!("Failed to remove Linux nftables ruleset: {e}");
            }
            currently_enforcing = false;
            last_baseline = None;
            last_config_version = None;
            last_redirect_ipv6 = None;
            last_connectivity_prewarm = None;
            {
                let mut guard = engine.state.lock().unwrap();
                guard.active_wfp_filters = 0;
                guard.tracked_processes.clear();
            }

            if let Some(flag) = nfqueue_stop.take() {
                flag.store(true, Ordering::Relaxed);
            }
            nfqueue_ready.store(false, Ordering::Release);
            if let Some(handle) = nfqueue_handle.take() {
                let _ = tokio::task::spawn_blocking(move || {
                    let _ = handle.join();
                })
                .await;
            }
            info!("Linux nftables enforcement paused/disabled; full network access restored");
        }
    }

    let _ = firewall.purge_all();
    if let Some(flag) = nfqueue_stop.take() {
        flag.store(true, Ordering::Relaxed);
    }
    nfqueue_ready.store(false, Ordering::Release);
    if let Some(handle) = nfqueue_handle.take() {
        let _ = tokio::task::spawn_blocking(move || {
            let _ = handle.join();
        })
        .await;
    }
}

#[cfg(target_os = "linux")]
fn evaluate_linux_packet(
    engine: &crate::engine::ServiceEngine,
    ctx: &curb_nftables::PacketContext,
    policy_ct_mark: u32,
) -> curb_nftables::NfqueueVerdict {
    use chrono::Utc;
    use curb_core::ipc::BlockedEvent;
    use curb_core::verify::BinaryIdentity;
    use curb_nftables::{L4Proto, NfqueueVerdict};
    use tracing::debug;
    use uuid::Uuid;

    use crate::engine::TrackedProcess;

    let Some(path) = &ctx.exe_path else {
        let guard = engine.state.lock().unwrap();
        if !guard.config.mode.is_actively_enforcing(Utc::now()) {
            return NfqueueVerdict::Accept;
        }
        debug!(
            "NFQUEUE drop (unresolved PID/exe) for {:?} {}:{} -> {}:{}",
            ctx.tuple.proto,
            ctx.tuple.src_ip,
            ctx.tuple.src_port,
            ctx.tuple.dst_ip,
            ctx.tuple.dst_port
        );
        return NfqueueVerdict::Drop;
    };

    let identity = match engine.adaptors.verifier.inspect_binary(path) {
        Ok(id) => id,
        Err(_) => {
            // If an upgraded binary was unlinked on disk while still running,
            // fall back to a path-only identity so path-based rules still match.
            let filename = path
                .file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_default();
            BinaryIdentity {
                path: path.to_string_lossy().to_string(),
                filename,
                sha256: String::new(),
                signature: None,
                product_name: None,
                original_filename: None,
                file_description: None,
            }
        }
    };

    let mut guard = engine.state.lock().unwrap();
    if !guard.config.mode.is_actively_enforcing(Utc::now()) {
        return NfqueueVerdict::Accept;
    }

    // Permit Linux OS connectivity probes (NetworkManager / ConnMan / systemd-networkd)
    // to resolved connectivity-check endpoints on HTTP/HTTPS when baseline NCSI is enabled.
    if guard.config.baseline.ncsi
        && ctx.tuple.proto == L4Proto::Tcp
        && matches!(ctx.tuple.dst_port, 80 | 443)
        && is_linux_connectivity_daemon(&identity.filename)
        && guard.ncsi_allowed_ips().contains(&ctx.tuple.dst_ip)
    {
        return NfqueueVerdict::AcceptAndMark(policy_ct_mark);
    }

    let matched = guard
        .evaluate_process(ctx.ppid, &identity)
        .or_else(|| evaluate_proton_wine_game(&guard, engine, ctx.pid, &identity));

    if let Some((rule_label, network, subprocesses)) = matched {
        let proto_ok = match ctx.tuple.proto {
            L4Proto::Tcp => network.allow_tcp,
            L4Proto::Udp => network.allow_udp,
        };
        if proto_ok {
            let ip_ok = match &network.dns_whitelist {
                None => true,
                Some(patterns) => {
                    let allowed_ips = guard.dns_cache.allowed_ips_for_patterns(patterns);
                    allowed_ips.contains(&ctx.tuple.dst_ip)
                        || (ctx.tuple.proto == L4Proto::Udp
                            && is_lan_multicast_cast(ctx.tuple.dst_ip, ctx.tuple.dst_port))
                }
            };
            if ip_ok {
                if let Some(p) = ctx.pid {
                    guard.tracked_processes.insert(
                        p,
                        TrackedProcess {
                            pid: p,
                            identity: identity.clone(),
                            rule_label,
                            network,
                            allow_subprocesses: subprocesses,
                            dynamic_filter_ids: Vec::new(),
                        },
                    );
                }
                return NfqueueVerdict::AcceptAndMark(policy_ct_mark);
            }
        }
    }

    let resolved_domain = guard.dns_cache.domain_for_ip(ctx.tuple.dst_ip);
    let is_steam_community = resolved_domain
        .as_deref()
        .and_then(|d| guard.presets.classify_blocked_domain(d))
        .is_some_and(|h| h.is_steam_community);
    let dest = match resolved_domain {
        Some(domain) => format!("{domain}:{}", ctx.tuple.dst_port),
        None => format!("{}:{}", ctx.tuple.dst_ip, ctx.tuple.dst_port),
    };

    guard.record_blocked_event(BlockedEvent {
        id: Uuid::new_v4(),
        timestamp: Utc::now(),
        app_name: identity.filename.clone(),
        exe: identity.filename,
        path: identity.path,
        destination: dest,
        signed: false,
        signer: None,
        is_steam_community,
    });
    NfqueueVerdict::Drop
}

#[cfg(target_os = "linux")]
fn is_linux_connectivity_daemon(filename: &str) -> bool {
    matches!(
        filename.to_ascii_lowercase().as_str(),
        "networkmanager" | "connmand" | "systemd-networkd"
    )
}

#[cfg(target_os = "linux")]
fn is_proton_or_wine_loader(identity: &curb_core::verify::BinaryIdentity) -> bool {
    let fname = identity.filename.to_ascii_lowercase();
    if !matches!(
        fname.as_str(),
        "wine64-preloader" | "wine-preloader" | "wine64" | "wine" | "wineserver"
    ) {
        return false;
    }
    let path_lower = identity.path.to_ascii_lowercase();
    path_lower.contains("/proton")
        || path_lower.contains("/compatibilitytools.d/")
        || path_lower.starts_with("/usr/bin/wine")
        || path_lower.starts_with("/usr/lib/wine")
}

/// Resolves Windows `.exe` games running under Proton/Wine on Linux where `/proc/<pid>/exe`
/// points to `wine64-preloader` instead of the game binary. Only activates for genuine
/// Wine/Proton loader binaries and still verifies the target `.exe` inside the allowed
/// `SteamGame`'s `install_dir`.
#[cfg(target_os = "linux")]
fn evaluate_proton_wine_game(
    guard: &crate::engine::EngineState,
    engine: &crate::engine::ServiceEngine,
    pid: Option<u32>,
    loader_identity: &curb_core::verify::BinaryIdentity,
) -> Option<(
    String,
    curb_core::config::NetworkPolicy,
    curb_core::config::SubprocessPolicy,
)> {
    use std::path::PathBuf;

    if !is_proton_or_wine_loader(loader_identity) {
        return None;
    }
    let pid = pid?;
    let cmdline = curb_linux::proc_net::read_proc_cmdline(pid);
    if cmdline.is_empty() {
        return None;
    }

    for rule in &guard.config.rules {
        if !rule.enabled || guard.is_rule_playtime_expired(rule.id) {
            continue;
        }
        let curb_core::config::ExecutableMatcher::SteamGame { install_dir, .. } = &rule.matcher
        else {
            continue;
        };
        if let Some(exe_path) = match_proton_cmdline_to_install_dir(&cmdline, install_dir) {
            if let Ok(game_identity) = engine.adaptors.verifier.inspect_binary(&PathBuf::from(&exe_path)) {
                if rule.matcher.matches(&game_identity)
                    || rule.subprocesses != curb_core::config::SubprocessPolicy::Disabled
                {
                    return Some((
                        format!("{} (Proton)", rule.name),
                        rule.network.clone(),
                        rule.subprocesses,
                    ));
                }
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn match_proton_cmdline_to_install_dir(cmdline: &[String], install_dir: &str) -> Option<String> {
    let norm_dir = install_dir
        .replace('\\', "/")
        .trim_end_matches('/')
        .to_ascii_lowercase();
    if norm_dir.is_empty() {
        return None;
    }
    let dir_prefix = format!("{norm_dir}/");

    for arg in cmdline {
        // Wine/Proton converts Linux paths to `Z:\home\user\...\Game.exe` or keeps `/home/.../Game.exe`.
        let mut candidate = arg.replace('\\', "/");
        if candidate.len() >= 2
            && candidate.as_bytes()[0].eq_ignore_ascii_case(&b'z')
            && candidate.as_bytes()[1] == b':'
        {
            candidate = candidate[2..].to_string();
        }
        let lower = candidate.to_ascii_lowercase();
        if lower.ends_with(".exe") && lower.starts_with(&dir_prefix) {
            if std::path::Path::new(&candidate).is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn is_lan_multicast_cast(ip: std::net::IpAddr, port: u16) -> bool {
    matches!(port, 1900 | 5353)
        && match ip {
            std::net::IpAddr::V4(v4) => v4.is_multicast(),
            std::net::IpAddr::V6(v6) => v6.is_multicast(),
        }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;

    use curb_core::verify::BinaryIdentity;
    use curb_nftables::{L4Proto, NfqueueVerdict, PacketContext, PacketTuple};
    use uuid::Uuid;

    #[test]
    fn permits_linux_connectivity_daemon_when_ncsi_ip_cached() {
        let dir = std::env::temp_dir().join(format!("curb_lx_ncsi_{}", Uuid::new_v4()));
        let engine = crate::engine::ServiceEngine::new(dir.clone()).unwrap();
        let probe_ip = IpAddr::V4(Ipv4Addr::new(95, 217, 163, 246));
        {
            let mut guard = engine.state.lock().unwrap();
            guard.dns_cache.record("ping.archlinux.org", &[probe_ip], 300);
        }

        let ctx = PacketContext {
            tuple: PacketTuple {
                proto: L4Proto::Tcp,
                src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
                src_port: 44444,
                dst_ip: probe_ip,
                dst_port: 80,
            },
            pid: Some(1234),
            ppid: Some(1),
            exe_path: Some(PathBuf::from("/usr/bin/NetworkManager")),
        };

        let verdict = evaluate_linux_packet(&engine, &ctx, 0x4356_0001);
        assert_eq!(verdict, NfqueueVerdict::AcceptAndMark(0x4356_0001));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn annotates_blocked_event_with_cached_domain_and_steam_community_flag() {
        let dir = std::env::temp_dir().join(format!("curb_lx_blk_{}", Uuid::new_v4()));
        let engine = crate::engine::ServiceEngine::new(dir.clone()).unwrap();
        let comm_ip = IpAddr::V4(Ipv4Addr::new(23, 55, 10, 10));
        {
            let mut guard = engine.state.lock().unwrap();
            guard.dns_cache.record("steamcommunity.com", &[comm_ip], 300);
        }

        let ctx = PacketContext {
            tuple: PacketTuple {
                proto: L4Proto::Tcp,
                src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
                src_port: 55555,
                dst_ip: comm_ip,
                dst_port: 443,
            },
            pid: Some(9999),
            ppid: Some(1),
            exe_path: Some(PathBuf::from("/usr/bin/curl")),
        };

        let verdict = evaluate_linux_packet(&engine, &ctx, 0x4356_0001);
        assert_eq!(verdict, NfqueueVerdict::Drop);

        let guard = engine.state.lock().unwrap();
        let ev = guard.blocked_events.front().expect("recorded blocked event");
        assert_eq!(ev.destination, "steamcommunity.com:443");
        assert!(ev.is_steam_community);

        drop(guard);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn matches_proton_wine_cmdline_inside_install_dir() {
        let dir = std::env::temp_dir().join(format!("curb_proton_{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let game_exe = dir.join("Game.exe");
        std::fs::write(&game_exe, b"MZfake").unwrap();

        let wine_arg = format!("Z:{}", game_exe.to_string_lossy().replace('/', "\\"));
        let cmdline = vec![wine_arg, "--fullscreen".into()];
        let matched = match_proton_cmdline_to_install_dir(&cmdline, &dir.to_string_lossy());
        assert_eq!(matched, Some(game_exe.to_string_lossy().to_string()));

        let loader = BinaryIdentity {
            path: "/home/user/.local/share/Steam/steamapps/common/Proton - Experimental/files/bin/wine64-preloader".into(),
            filename: "wine64-preloader".into(),
            sha256: String::new(),
            signature: None,
            product_name: None,
            original_filename: None,
            file_description: None,
        };
        assert!(is_proton_or_wine_loader(&loader));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
