#[cfg(target_os = "linux")]
pub async fn run_linux_enforcement_loop(
    engine: crate::engine::ServiceEngine,
    dns_proxy_port: u16,
    fallback_upstream: std::net::SocketAddr,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    use std::net::IpAddr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use chrono::Utc;
    use curb_core::adaptors::{DnsManager, FirewallManager};
    use curb_core::ipc::BlockedEvent;
    use curb_core::verify::inspect_binary;
    use curb_linux::LinuxDnsManager;
    use curb_nftables::{
        run_nfqueue_loop, L4Proto, NftablesFirewall, PacketContext, CURB_NFQUEUE_NUM,
    };
    use tracing::{info, warn};
    use uuid::Uuid;

    use crate::engine::TrackedProcess;

    let is_root = unsafe { libc::geteuid() == 0 };
    if !is_root {
        warn!("curb-service is running without root/CAP_NET_ADMIN; Linux nftables/NFQUEUE enforcement disabled (dev mode)");
        let _ = shutdown.changed().await;
        return;
    }

    let dns_mgr = LinuxDnsManager;
    let firewall = NftablesFirewall;

    let mut upstreams = dns_mgr.discover_upstreams();
    if !upstreams.contains(&fallback_upstream) {
        upstreams.push(fallback_upstream);
    }
    engine.set_upstream_dns(upstreams);

    let mut nfqueue_stop: Option<Arc<AtomicBool>> = None;
    let mut nfqueue_handle: Option<std::thread::JoinHandle<()>> = None;
    let mut currently_enforcing = false;
    let mut last_baseline = None;

    let mut tick = tokio::time::interval(Duration::from_secs(2));
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    info!("Linux enforcement loop shutting down — cleaning up nftables");
                    break;
                }
            }
            _ = engine.reconcile_notify.notified() => {}
            _ = tick.tick() => {}
        }

        let (should_enforce, baseline) = {
            let guard = engine.state.lock().unwrap();
            (
                guard.config.mode.is_actively_enforcing(Utc::now()),
                guard.config.baseline.clone(),
            )
        };

        if should_enforce {
            if nfqueue_handle.is_none() {
                let stop_flag = Arc::new(AtomicBool::new(false));
                let stop_clone = stop_flag.clone();
                let eng = engine.clone();
                match std::thread::Builder::new()
                    .name("curb-nfqueue".into())
                    .spawn(move || {
                        let res = run_nfqueue_loop(CURB_NFQUEUE_NUM, stop_clone, |ctx: &PacketContext| {
                            evaluate_linux_packet(&eng, ctx)
                        });
                        if let Err(e) = res {
                            warn!("Curb NFQUEUE loop exited with error: {e}");
                        }
                    }) {
                    Ok(handle) => {
                        nfqueue_stop = Some(stop_flag);
                        nfqueue_handle = Some(handle);
                    }
                    Err(e) => {
                        warn!("Failed to spawn NFQUEUE thread: {e}");
                        continue;
                    }
                }
            }

            if !currently_enforcing || last_baseline.as_ref() != Some(&baseline) {
                match firewall.apply_enforcing(&baseline, dns_proxy_port) {
                    Ok(()) => {
                        currently_enforcing = true;
                        last_baseline = Some(baseline);
                        engine.state.lock().unwrap().active_wfp_filters = 1;
                        info!("Linux nftables default-deny enforcement active (queue {CURB_NFQUEUE_NUM}, DNS redirect -> :{dns_proxy_port})");
                    }
                    Err(e) => {
                        warn!("Failed to apply Linux nftables ruleset: {e}");
                    }
                }
            }
        } else if currently_enforcing {
            if let Err(e) = firewall.purge_all() {
                warn!("Failed to remove Linux nftables ruleset: {e}");
            }
            currently_enforcing = false;
            last_baseline = None;
            engine.state.lock().unwrap().active_wfp_filters = 0;

            if let Some(flag) = nfqueue_stop.take() {
                flag.store(true, Ordering::Relaxed);
            }
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
    if let Some(handle) = nfqueue_handle.take() {
        let _ = tokio::task::spawn_blocking(move || {
            let _ = handle.join();
        })
        .await;
    }

    fn evaluate_linux_packet(engine: &crate::engine::ServiceEngine, ctx: &PacketContext) -> bool {
        let Some(path) = &ctx.exe_path else {
            let guard = engine.state.lock().unwrap();
            return !guard.config.mode.is_actively_enforcing(Utc::now());
        };
        let Ok(identity) = inspect_binary(path) else {
            return false;
        };

        let mut guard = engine.state.lock().unwrap();
        if !guard.config.mode.is_actively_enforcing(Utc::now()) {
            return true;
        }

        if let Some((rule_label, network, subprocesses)) =
            guard.evaluate_process(ctx.ppid, &identity)
        {
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
                        guard
                            .tracked_processes
                            .entry(p)
                            .or_insert_with(|| TrackedProcess {
                                pid: p,
                                identity: identity.clone(),
                                rule_label,
                                network,
                                allow_subprocesses: subprocesses,
                                dynamic_filter_ids: Vec::new(),
                            });
                    }
                    return true;
                }
            }
        }

        let dest = format!("{}:{}", ctx.tuple.dst_ip, ctx.tuple.dst_port);
        guard.record_blocked_event(BlockedEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            app_name: identity.filename.clone(),
            exe: identity.filename,
            path: identity.path,
            destination: dest,
            signed: false,
            signer: None,
            is_steam_community: false,
        });
        false
    }

    fn is_lan_multicast_cast(ip: IpAddr, port: u16) -> bool {
        matches!(port, 1900 | 5353)
            && match ip {
                IpAddr::V4(v4) => v4.is_multicast(),
                IpAddr::V6(v6) => v6.is_multicast(),
            }
    }
}
