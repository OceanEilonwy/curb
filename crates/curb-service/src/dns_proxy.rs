use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use curb_core::ipc::BlockedEvent;
use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::engine::{LockExt, ServiceEngine};

const MAX_CONCURRENT_DNS_QUERIES: usize = 256;

/// Async local DNS proxy listening on IPv4 (`127.0.0.1:53`) and IPv6 (`[::1]:53`)
/// over both UDP and TCP.
///
/// Handles queries concurrently, forwards allowed queries to the adapter's original
/// upstream DNS servers (falling back to `upstream` / `8.8.8.8:53`), records returned
/// A/AAAA records into Curb's `DnsCache` with TTLs (waking WFP reconciliation
/// immediately), and returns `REFUSED` for blocked domains.
pub async fn run_dns_proxy(
    engine: ServiceEngine,
    bind_addr: SocketAddr,
    upstream: SocketAddr,
) -> std::io::Result<()> {
    let udp_v4 = Arc::new(UdpSocket::bind(bind_addr).await?);

    // Best-effort IPv6 loopback UDP listener on the same port when bound to IPv4 loopback.
    let v6_addr = if bind_addr.ip().is_loopback() && bind_addr.is_ipv4() {
        Some(SocketAddr::new(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            bind_addr.port(),
        ))
    } else {
        None
    };

    let udp_v6 = match v6_addr {
        Some(addr) => match UdpSocket::bind(addr).await {
            Ok(sock) => {
                info!("Curb local DNS proxy listening on {addr} (UDP)");
                Some(Arc::new(sock))
            }
            Err(e) => {
                warn!("Could not bind IPv6 UDP DNS proxy on {addr}: {e}");
                None
            }
        },
        None => None,
    };

    let permits = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_DNS_QUERIES));

    // Best-effort TCP DNS listeners (RFC 1035, required for large responses / DNSSEC).
    if let Ok(tcp_v4) = TcpListener::bind(bind_addr).await {
        let eng = engine.clone();
        let sem = permits.clone();
        tokio::spawn(async move {
            run_tcp_loop(tcp_v4, eng, upstream, sem).await;
        });
    } else {
        warn!("Could not bind IPv4 TCP DNS proxy on {bind_addr}");
    }

    if let Some(addr) = v6_addr {
        if let Ok(tcp_v6) = TcpListener::bind(addr).await {
            let eng = engine.clone();
            let sem = permits.clone();
            tokio::spawn(async move {
                run_tcp_loop(tcp_v6, eng, upstream, sem).await;
            });
        }
    }

    engine.set_dns_ready(true, udp_v6.is_some());
    info!(
        "Curb local DNS proxy listening on {bind_addr} (UDP/TCP, ipv6={}) -> fallback upstream {upstream}",
        udp_v6.is_some()
    );

    if let Some(sock_v6) = udp_v6 {
        let eng = engine.clone();
        let sem = permits.clone();
        tokio::spawn(async move {
            if let Err(e) = run_udp_loop(sock_v6, eng, upstream, sem).await {
                warn!("IPv6 UDP DNS loop exited: {e}");
            }
        });
    }

    let res = run_udp_loop(udp_v4, engine.clone(), upstream, permits).await;
    engine.set_dns_ready(false, false);
    res
}

async fn run_udp_loop(
    socket: Arc<UdpSocket>,
    engine: ServiceEngine,
    fallback_upstream: SocketAddr,
    permits: Arc<tokio::sync::Semaphore>,
) -> std::io::Result<()> {
    let mut buf = [0u8; 4096];
    loop {
        let (len, peer) = match socket.recv_from(&mut buf).await {
            Ok(res) => res,
            Err(e) => {
                // On Windows, an ICMP Port Unreachable for a previous `send_to` (e.g. a
                // client that timed out and closed its ephemeral UDP port) surfaces as
                // `WSAECONNRESET` (10054) on the next `recv_from`. Never terminate the
                // DNS proxy on transient socket errors.
                debug!("DNS UDP recv_from error (ignoring): {e}");
                continue;
            }
        };
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            debug!("DNS proxy at max concurrency ({MAX_CONCURRENT_DNS_QUERIES}); dropping burst packet from {peer}");
            continue;
        };
        let packet = buf[..len].to_vec();
        let sock = socket.clone();
        let eng = engine.clone();

        tokio::spawn(async move {
            let _permit = permit;
            if let Some(resp_bytes) =
                handle_dns_packet(&eng, &packet, fallback_upstream, false).await
            {
                if let Err(e) = sock.send_to(&resp_bytes, peer).await {
                    debug!("DNS UDP reply send error to {peer}: {e}");
                }
            }
        });
    }
}

async fn run_tcp_loop(
    listener: TcpListener,
    engine: ServiceEngine,
    fallback_upstream: SocketAddr,
    permits: Arc<tokio::sync::Semaphore>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, _peer)) => {
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    debug!("DNS TCP proxy at max concurrency; dropping connection");
                    continue;
                };
                let eng = engine.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let _ = handle_tcp_client(stream, eng, fallback_upstream).await;
                });
            }
            Err(e) => {
                debug!("DNS TCP accept error (ignoring): {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

async fn handle_tcp_client(
    mut stream: TcpStream,
    engine: ServiceEngine,
    fallback_upstream: SocketAddr,
) -> std::io::Result<()> {
    // Support RFC 7766 persistent TCP DNS connections (multiple queries per stream).
    for _ in 0..64 {
        let mut len_buf = [0u8; 2];
        match tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut len_buf)).await {
            Ok(Ok(_)) => {}
            _ => return Ok(()),
        }
        let msg_len = u16::from_be_bytes(len_buf) as usize;
        if msg_len == 0 || msg_len > 65535 {
            return Ok(());
        }

        let mut packet = vec![0u8; msg_len];
        match tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut packet)).await {
            Ok(Ok(_)) => {}
            _ => return Ok(()),
        }

        if let Some(resp_bytes) = handle_dns_packet(&engine, &packet, fallback_upstream, true).await
        {
            if resp_bytes.len() <= u16::MAX as usize {
                let out_len = (resp_bytes.len() as u16).to_be_bytes();
                if stream.write_all(&out_len).await.is_err()
                    || stream.write_all(&resp_bytes).await.is_err()
                {
                    return Ok(());
                }
            }
        }
    }
    Ok(())
}

/// Pre-resolves Microsoft NCSI probe hosts through Curb's upstream forwarder so
/// `svchost.exe` receives dynamic WFP permission for NCSI HTTP checks immediately
/// when Curb transitions into enforcing mode and stays refreshed before TTL expiry.
#[cfg_attr(not(windows), allow(dead_code))]
pub async fn prewarm_ncsi_dns(engine: &ServiceEngine, fallback_upstream: SocketAddr) {
    let probes = [
        ("www.msftconnecttest.com.", RecordType::A),
        ("www.msftconnecttest.com.", RecordType::AAAA),
        ("www.msftncsi.com.", RecordType::A),
        ("www.msftncsi.com.", RecordType::AAAA),
        ("ipv6.msftconnecttest.com.", RecordType::AAAA),
        ("ipv6.msftncsi.com.", RecordType::AAAA),
        ("dns.msftncsi.com.", RecordType::A),
        ("dns.msftncsi.com.", RecordType::AAAA),
    ];
    for (idx, (host, rtype)) in probes.iter().enumerate() {
        let Ok(name) = Name::from_utf8(*host) else {
            continue;
        };
        let mut msg = Message::new();
        msg.set_id(0x4355u16.wrapping_add(idx as u16));
        msg.set_message_type(MessageType::Query);
        msg.set_recursion_desired(true);
        msg.add_query(Query::query(name, *rtype));
        if let Ok(packet) = msg.to_vec() {
            let _ = handle_dns_packet(engine, &packet, fallback_upstream, false).await;
        }
    }
}

/// Pre-resolves Linux NetworkManager / ConnMan connectivity-check hosts through
/// Curb's upstream forwarder so NFQUEUE permits OS connectivity probes immediately
/// when Curb transitions into enforcing mode.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub async fn prewarm_linux_connectivity_dns(engine: &ServiceEngine, fallback_upstream: SocketAddr) {
    let mut probes: Vec<(String, RecordType)> = Vec::new();
    for host in curb_core::dns::LINUX_CONNECTIVITY_DOMAINS {
        let fqdn = format!("{host}.");
        if *host == "ipv4.connman.net" {
            probes.push((fqdn, RecordType::A));
        } else if *host == "ipv6.connman.net" {
            probes.push((fqdn, RecordType::AAAA));
        } else {
            probes.push((fqdn.clone(), RecordType::A));
            probes.push((fqdn, RecordType::AAAA));
        }
    }
    for (idx, (host, rtype)) in probes.iter().enumerate() {
        let Ok(name) = Name::from_utf8(host.as_str()) else {
            continue;
        };
        let mut msg = Message::new();
        msg.set_id(0x4360u16.wrapping_add(idx as u16));
        msg.set_message_type(MessageType::Query);
        msg.set_recursion_desired(true);
        msg.add_query(Query::query(name, *rtype));
        if let Ok(packet) = msg.to_vec() {
            let _ = handle_dns_packet(engine, &packet, fallback_upstream, false).await;
        }
    }
}

async fn handle_dns_packet(
    engine: &ServiceEngine,
    packet: &[u8],
    fallback_upstream: SocketAddr,
    prefer_tcp: bool,
) -> Option<Vec<u8>> {
    let query = Message::from_vec(packet).ok()?;
    let queried_domain = query
        .queries()
        .first()
        .map(|q| q.name().to_utf8())
        .unwrap_or_default();

    let allowed = {
        let guard = engine.state.lock_or_recover();
        guard.is_dns_query_allowed(&queried_domain)
    };

    if !allowed {
        debug!("DNS blocked: {queried_domain}");
        {
            let mut guard = engine.state.lock_or_recover();
            let clean_domain = queried_domain.trim_end_matches('.').to_string();
            let hint = guard.presets.classify_blocked_domain(&clean_domain);
            let (app_name, is_steam_community) = match hint {
                Some(h) => (h.app_name, h.is_steam_community),
                None => ("DNS Request".into(), false),
            };
            guard.record_blocked_event(BlockedEvent {
                id: Uuid::new_v4(),
                timestamp: Utc::now(),
                app_name,
                exe: "dnscache".into(),
                path: String::new(),
                destination: clean_domain,
                signed: true,
                signer: None,
                is_steam_community,
            });
        }
        let mut reply = Message::new();
        reply.set_id(query.id());
        reply.set_message_type(MessageType::Response);
        reply.set_recursion_desired(query.recursion_desired());
        reply.set_recursion_available(true);
        reply.set_response_code(ResponseCode::Refused);
        for q in query.queries() {
            reply.add_query(q.clone());
        }
        return reply.to_vec().ok();
    }

    let upstreams = engine.upstream_dns_servers(fallback_upstream);
    let resp_bytes = forward_to_upstreams(packet, &upstreams, prefer_tcp).await?;

    // Parse CNAME, A, and AAAA records into Curb's TTL cache
    if let Ok(resp_msg) = Message::from_vec(&resp_bytes) {
        let mut ips = Vec::new();
        let mut cnames = Vec::new();
        let mut min_ttl = u32::MAX;
        for ans in resp_msg.answers() {
            if let Some(rdata) = ans.data() {
                match rdata {
                    RData::A(a) => {
                        ips.push(IpAddr::V4(a.0));
                        min_ttl = min_ttl.min(ans.ttl());
                    }
                    RData::AAAA(aaaa) => {
                        ips.push(IpAddr::V6(aaaa.0));
                        min_ttl = min_ttl.min(ans.ttl());
                    }
                    RData::CNAME(cname) => {
                        cnames.push((ans.name().to_utf8(), cname.0.to_utf8()));
                    }
                    _ => {}
                }
            }
        }
        if (!ips.is_empty() || !cnames.is_empty()) && !queried_domain.is_empty() {
            let mut ttl = if min_ttl == u32::MAX { 60 } else { min_ttl };
            let ncsi_patterns: Vec<String> = crate::engine::NCSI_DOMAINS
                .iter()
                .map(|s| (*s).to_string())
                .collect();
            let sync_target = {
                let mut guard = engine.state.lock_or_recover();
                for (owner, target) in &cnames {
                    guard.dns_cache.record_cname(owner, &queried_domain);
                    guard.dns_cache.record_cname(target, owner);
                }
                let origin = guard.dns_cache.origin_for_domain(&queried_domain);
                if curb_core::dns::domain_matches_any(&queried_domain, &ncsi_patterns)
                    || origin
                        .as_deref()
                        .is_some_and(|o| curb_core::dns::domain_matches_any(o, &ncsi_patterns))
                {
                    ttl = ttl.max(600);
                }
                if !ips.is_empty() && guard.dns_cache.record(&queried_domain, &ips, ttl) {
                    Some(guard.dns_cache.version())
                } else {
                    None
                }
            };
            if let Some(target_version) = sync_target {
                engine.notify_reconcile();
                engine
                    .wait_for_wfp_dns_sync(target_version, Duration::from_millis(400))
                    .await;
            }
        }
    }

    Some(resp_bytes)
}

async fn forward_to_upstreams(
    packet: &[u8],
    upstreams: &[SocketAddr],
    prefer_tcp: bool,
) -> Option<Vec<u8>> {
    if upstreams.is_empty() {
        return None;
    }
    if upstreams.len() == 1 {
        return forward_one(packet, upstreams[0], Duration::from_millis(2500), prefer_tcp).await;
    }

    // Staggered parallel race: give the first upstream (typically the adapter's original
    // router/ISP/VPN resolver) a 120ms head start, then fire fallback resolvers concurrently.
    // Never let a fallback NXDOMAIN/SERVFAIL/Refused preempt an in-flight primary upstream
    // (preserves split-horizon LAN/VPN DNS such as Tailscale MagicDNS).
    let mut set = tokio::task::JoinSet::new();
    for (idx, &upstream) in upstreams.iter().take(4).enumerate() {
        let pkt = packet.to_vec();
        set.spawn(async move {
            if idx > 0 {
                tokio::time::sleep(Duration::from_millis(120 * idx as u64)).await;
            }
            let resp = forward_one(&pkt, upstream, Duration::from_millis(2500), prefer_tcp).await;
            (idx, resp)
        });
    }

    let mut primary_done = false;
    let mut fallback_err: Option<Vec<u8>> = None;

    while let Some(joined) = set.join_next().await {
        let Ok((idx, resp_opt)) = joined else {
            continue;
        };
        if idx == 0 {
            primary_done = true;
            if let Some(resp) = resp_opt {
                set.abort_all();
                return Some(resp);
            }
            if let Some(err_resp) = fallback_err.take() {
                set.abort_all();
                return Some(err_resp);
            }
        } else if let Some(resp) = resp_opt {
            let is_positive = Message::from_vec(&resp)
                .map(|m| m.response_code() == ResponseCode::NoError)
                .unwrap_or(false);
            if is_positive || primary_done {
                set.abort_all();
                return Some(resp);
            }
            fallback_err.get_or_insert(resp);
        }
    }
    fallback_err
}

async fn forward_one(
    packet: &[u8],
    upstream: SocketAddr,
    timeout: Duration,
    prefer_tcp: bool,
) -> Option<Vec<u8>> {
    if prefer_tcp {
        return forward_tcp(packet, upstream, timeout).await;
    }
    let resp = forward_udp(packet, upstream, timeout).await?;
    if let Ok(parsed) = Message::from_vec(&resp) {
        if parsed.truncated() {
            if let Some(tcp_resp) = forward_tcp(packet, upstream, timeout).await {
                return Some(tcp_resp);
            }
        }
    }
    Some(resp)
}

async fn forward_udp(packet: &[u8], upstream: SocketAddr, timeout: Duration) -> Option<Vec<u8>> {
    let bind_local = if upstream.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let sock = UdpSocket::bind(bind_local).await.ok()?;
    #[cfg(target_os = "linux")]
    if let Err(e) = curb_linux::dns::set_curb_fw_mark(&sock) {
        if unsafe { libc::geteuid() == 0 } {
            warn!("Failed to set SO_MARK on upstream UDP DNS socket to {upstream}: {e}");
            return None;
        }
    }
    sock.connect(upstream).await.ok()?;
    sock.send(packet).await.ok()?;

    let mut resp_buf = [0u8; 4096];
    let resp_len = tokio::time::timeout(timeout, sock.recv(&mut resp_buf))
        .await
        .ok()?
        .ok()?;
    Some(resp_buf[..resp_len].to_vec())
}

async fn forward_tcp(packet: &[u8], upstream: SocketAddr, timeout: Duration) -> Option<Vec<u8>> {
    if packet.len() > u16::MAX as usize {
        return None;
    }
    #[cfg(target_os = "linux")]
    let mut stream = {
        let tcp_sock = if upstream.is_ipv6() {
            tokio::net::TcpSocket::new_v6().ok()?
        } else {
            tokio::net::TcpSocket::new_v4().ok()?
        };
        if let Err(e) = curb_linux::dns::set_curb_fw_mark(&tcp_sock) {
            if unsafe { libc::geteuid() == 0 } {
                warn!("Failed to set SO_MARK on upstream TCP DNS socket to {upstream}: {e}");
                return None;
            }
        }
        tokio::time::timeout(timeout, tcp_sock.connect(upstream))
            .await
            .ok()?
            .ok()?
    };
    #[cfg(not(target_os = "linux"))]
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(upstream))
        .await
        .ok()?
        .ok()?;

    let len_bytes = (packet.len() as u16).to_be_bytes();
    tokio::time::timeout(timeout, async {
        stream.write_all(&len_bytes).await?;
        stream.write_all(packet).await?;

        let mut resp_len_buf = [0u8; 2];
        stream.read_exact(&mut resp_len_buf).await?;
        let resp_len = u16::from_be_bytes(resp_len_buf) as usize;
        if resp_len == 0 || resp_len > 65535 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid DNS TCP length",
            ));
        }
        let mut resp = vec![0u8; resp_len];
        stream.read_exact(&mut resp).await?;
        Ok(resp)
    })
    .await
    .ok()?
    .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::Record;

    #[tokio::test]
    async fn forwards_allowed_queries_caches_ips_and_refuses_blocked_domains() {
        let dir = std::env::temp_dir().join(format!("curb_dns_test_{}", Uuid::new_v4()));
        let engine = ServiceEngine::new(dir.clone()).unwrap();

        // Disable Steam preset so only NCSI/NTP domains are allowed in enforcing mode.
        {
            let mut guard = engine.state.lock_or_recover();
            guard.config.presets.steam.enabled = false;
        }

        // Spin up a local mock upstream UDP DNS server that answers 203.0.113.42 for any query.
        let mock_upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = mock_upstream.local_addr().unwrap();
        let mock_task = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((len, peer)) = mock_upstream.recv_from(&mut buf).await {
                if let Ok(req) = Message::from_vec(&buf[..len]) {
                    let mut resp = Message::new();
                    resp.set_id(req.id());
                    resp.set_message_type(MessageType::Response);
                    resp.set_recursion_desired(true);
                    resp.set_recursion_available(true);
                    for q in req.queries() {
                        resp.add_query(q.clone());
                        resp.add_answer(Record::from_rdata(
                            q.name().clone(),
                            120,
                            RData::A(A(Ipv4Addr::new(203, 0, 113, 42))),
                        ));
                    }
                    if let Ok(bytes) = resp.to_vec() {
                        let _ = mock_upstream.send_to(&bytes, peer).await;
                    }
                }
            }
        });

        // Allowed NCSI query should forward, return IP, and populate dns_cache.
        let mut allowed_q = Message::new();
        allowed_q.set_id(0x1234);
        allowed_q.set_message_type(MessageType::Query);
        allowed_q.add_query(Query::query(
            Name::from_utf8("www.msftconnecttest.com.").unwrap(),
            RecordType::A,
        ));
        let allowed_resp = handle_dns_packet(&engine, &allowed_q.to_vec().unwrap(), upstream_addr, false)
            .await
            .expect("allowed DNS response");
        let parsed = Message::from_vec(&allowed_resp).unwrap();
        assert_eq!(parsed.response_code(), ResponseCode::NoError);
        {
            let guard = engine.state.lock_or_recover();
            assert_eq!(
                guard.ncsi_allowed_ips(),
                vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42))]
            );
        }

        // Blocked domain should return REFUSED without hitting upstream.
        let mut blocked_q = Message::new();
        blocked_q.set_id(0x5678);
        blocked_q.set_message_type(MessageType::Query);
        blocked_q.add_query(Query::query(
            Name::from_utf8("example.com.").unwrap(),
            RecordType::A,
        ));
        let blocked_resp = handle_dns_packet(&engine, &blocked_q.to_vec().unwrap(), upstream_addr, false)
            .await
            .expect("refused DNS response");
        let parsed_blocked = Message::from_vec(&blocked_resp).unwrap();
        assert_eq!(parsed_blocked.response_code(), ResponseCode::Refused);

        mock_task.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn handle_dns_packet_waits_for_wfp_sync_before_returning_reply() {
        let dir = std::env::temp_dir().join(format!("curb_dns_wfp_sync_{}", Uuid::new_v4()));
        let engine = ServiceEngine::new(dir.clone()).unwrap();
        engine.set_wfp_loop_active(true);

        let mock_upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = mock_upstream.local_addr().unwrap();
        let mock_task = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((len, peer)) = mock_upstream.recv_from(&mut buf).await {
                if let Ok(req) = Message::from_vec(&buf[..len]) {
                    let mut resp = Message::new();
                    resp.set_id(req.id());
                    resp.set_message_type(MessageType::Response);
                    resp.set_recursion_desired(true);
                    resp.set_recursion_available(true);
                    for q in req.queries() {
                        resp.add_query(q.clone());
                        resp.add_answer(Record::from_rdata(
                            q.name().clone(),
                            60,
                            RData::A(A(Ipv4Addr::new(198, 51, 100, 99))),
                        ));
                    }
                    if let Ok(bytes) = resp.to_vec() {
                        let _ = mock_upstream.send_to(&bytes, peer).await;
                    }
                }
            }
        });

        let applied_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let applied_bg = applied_flag.clone();
        let eng_bg = engine.clone();
        let sync_task = tokio::spawn(async move {
            eng_bg.reconcile_notify.notified().await;
            tokio::time::sleep(Duration::from_millis(30)).await;
            let ver = eng_bg.state.lock_or_recover().dns_cache.version();
            applied_bg.store(true, std::sync::atomic::Ordering::Release);
            eng_bg.mark_wfp_dns_applied(ver);
        });

        let mut q = Message::new();
        q.set_id(0x2222);
        q.set_message_type(MessageType::Query);
        q.add_query(Query::query(
            Name::from_utf8("store.steampowered.com.").unwrap(),
            RecordType::A,
        ));

        let resp = handle_dns_packet(&engine, &q.to_vec().unwrap(), upstream_addr, false)
            .await
            .expect("DNS response after WFP sync");
        assert!(
            applied_flag.load(std::sync::atomic::Ordering::Acquire),
            "handle_dns_packet returned before WFP filters were marked applied"
        );
        let parsed = Message::from_vec(&resp).unwrap();
        assert_eq!(parsed.response_code(), ResponseCode::NoError);

        sync_task.await.unwrap();
        mock_task.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn udp_proxy_survives_client_disconnect_and_respects_concurrency_cap() {
        let dir = std::env::temp_dir().join(format!("curb_dns_udp_resil_{}", Uuid::new_v4()));
        let engine = ServiceEngine::new(dir.clone()).unwrap();

        let mock_upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = mock_upstream.local_addr().unwrap();
        let mock_task = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((len, peer)) = mock_upstream.recv_from(&mut buf).await {
                if let Ok(req) = Message::from_vec(&buf[..len]) {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    let mut resp = Message::new();
                    resp.set_id(req.id());
                    resp.set_message_type(MessageType::Response);
                    resp.set_recursion_desired(true);
                    resp.set_recursion_available(true);
                    for q in req.queries() {
                        resp.add_query(q.clone());
                        resp.add_answer(Record::from_rdata(
                            q.name().clone(),
                            60,
                            RData::A(A(Ipv4Addr::new(203, 0, 113, 77))),
                        ));
                    }
                    if let Ok(bytes) = resp.to_vec() {
                        let _ = mock_upstream.send_to(&bytes, peer).await;
                    }
                }
            }
        });

        let proxy_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let proxy_addr = proxy_sock.local_addr().unwrap();
        let permits = Arc::new(tokio::sync::Semaphore::new(2));
        let loop_task = tokio::spawn(run_udp_loop(
            proxy_sock,
            engine.clone(),
            upstream_addr,
            permits.clone(),
        ));

        let mut q = Message::new();
        q.set_id(0x3333);
        q.set_message_type(MessageType::Query);
        q.add_query(Query::query(
            Name::from_utf8("store.steampowered.com.").unwrap(),
            RecordType::A,
        ));
        let pkt = q.to_vec().unwrap();

        // 1. Client sends a query and immediately drops its socket before reply arrives
        //    (triggers ICMP Port Unreachable / WSAECONNRESET on Windows).
        {
            let ephemeral = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            ephemeral.send_to(&pkt, proxy_addr).await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(40)).await;

        // 2. When concurrency permits are exhausted, burst packets are dropped without crashing.
        let held = permits.acquire_many(2).await.unwrap();
        let saturated_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        saturated_client.send_to(&pkt, proxy_addr).await.unwrap();
        let mut drop_buf = [0u8; 512];
        let timed_out = tokio::time::timeout(
            Duration::from_millis(60),
            saturated_client.recv(&mut drop_buf),
        )
        .await;
        assert!(timed_out.is_err(), "expected burst packet to be dropped when saturated");
        drop(held);

        // 3. Subsequent normal query still succeeds cleanly.
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(&pkt, proxy_addr).await.unwrap();
        let mut resp_buf = [0u8; 2048];
        let n = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut resp_buf))
            .await
            .expect("proxy reply timeout")
            .expect("proxy recv");
        let parsed = Message::from_vec(&resp_buf[..n]).unwrap();
        assert_eq!(parsed.response_code(), ResponseCode::NoError);

        loop_task.abort();
        mock_task.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn fallback_nxdomain_does_not_preempt_slower_primary_upstream() {
        // Primary (LAN/VPN) takes 200ms and returns NoError with 100.64.0.42.
        let primary_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let primary_addr = primary_sock.local_addr().unwrap();
        let primary_task = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            if let Ok((len, peer)) = primary_sock.recv_from(&mut buf).await {
                tokio::time::sleep(Duration::from_millis(200)).await;
                if let Ok(req) = Message::from_vec(&buf[..len]) {
                    let mut resp = Message::new();
                    resp.set_id(req.id());
                    resp.set_message_type(MessageType::Response);
                    resp.set_response_code(ResponseCode::NoError);
                    for q in req.queries() {
                        resp.add_query(q.clone());
                        resp.add_answer(Record::from_rdata(
                            q.name().clone(),
                            60,
                            RData::A(A(Ipv4Addr::new(100, 64, 0, 42))),
                        ));
                    }
                    if let Ok(bytes) = resp.to_vec() {
                        let _ = primary_sock.send_to(&bytes, peer).await;
                    }
                }
            }
        });

        // Fallback (public DNS) fires at 120ms and immediately returns NXDOMAIN.
        let fallback_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let fallback_addr = fallback_sock.local_addr().unwrap();
        let fallback_task = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            if let Ok((len, peer)) = fallback_sock.recv_from(&mut buf).await {
                if let Ok(req) = Message::from_vec(&buf[..len]) {
                    let mut resp = Message::new();
                    resp.set_id(req.id());
                    resp.set_message_type(MessageType::Response);
                    resp.set_response_code(ResponseCode::NXDomain);
                    for q in req.queries() {
                        resp.add_query(q.clone());
                    }
                    if let Ok(bytes) = resp.to_vec() {
                        let _ = fallback_sock.send_to(&bytes, peer).await;
                    }
                }
            }
        });

        let mut q = Message::new();
        q.set_id(0x7777);
        q.set_message_type(MessageType::Query);
        q.add_query(Query::query(
            Name::from_utf8("mybox.tailnet.ts.net.").unwrap(),
            RecordType::A,
        ));

        let resp = forward_to_upstreams(&q.to_vec().unwrap(), &[primary_addr, fallback_addr], false)
            .await
            .expect("primary upstream response");
        let parsed = Message::from_vec(&resp).unwrap();
        assert_eq!(parsed.response_code(), ResponseCode::NoError);
        assert_eq!(parsed.answers().len(), 1);

        primary_task.abort();
        fallback_task.abort();
    }

    #[tokio::test]
    async fn tcp_proxy_handles_multiple_queries_on_single_connection() {
        let dir = std::env::temp_dir().join(format!("curb_dns_tcp_multi_{}", Uuid::new_v4()));
        let engine = ServiceEngine::new(dir.clone()).unwrap();

        let mock_tcp_upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = mock_tcp_upstream.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            while let Ok((mut s, _)) = mock_tcp_upstream.accept().await {
                tokio::spawn(async move {
                    let mut lb = [0u8; 2];
                    if s.read_exact(&mut lb).await.is_ok() {
                        let len = u16::from_be_bytes(lb) as usize;
                        let mut p = vec![0u8; len];
                        if s.read_exact(&mut p).await.is_ok() {
                            if let Ok(req) = Message::from_vec(&p) {
                                let mut resp = Message::new();
                                resp.set_id(req.id());
                                resp.set_message_type(MessageType::Response);
                                for q in req.queries() {
                                    resp.add_query(q.clone());
                                    resp.add_answer(Record::from_rdata(
                                        q.name().clone(),
                                        60,
                                        RData::A(A(Ipv4Addr::new(203, 0, 113, 88))),
                                    ));
                                }
                                if let Ok(bytes) = resp.to_vec() {
                                    let _ = s.write_all(&(bytes.len() as u16).to_be_bytes()).await;
                                    let _ = s.write_all(&bytes).await;
                                }
                            }
                        }
                    }
                });
            }
        });

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let permits = Arc::new(tokio::sync::Semaphore::new(4));
        let tcp_task = tokio::spawn(run_tcp_loop(
            proxy_listener,
            engine.clone(),
            upstream_addr,
            permits,
        ));

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        for id in [0x1111u16, 0x2222u16] {
            let mut q = Message::new();
            q.set_id(id);
            q.set_message_type(MessageType::Query);
            q.add_query(Query::query(
                Name::from_utf8("store.steampowered.com.").unwrap(),
                RecordType::A,
            ));
            let pkt = q.to_vec().unwrap();
            client.write_all(&(pkt.len() as u16).to_be_bytes()).await.unwrap();
            client.write_all(&pkt).await.unwrap();

            let mut lb = [0u8; 2];
            client.read_exact(&mut lb).await.unwrap();
            let rlen = u16::from_be_bytes(lb) as usize;
            let mut rbuf = vec![0u8; rlen];
            client.read_exact(&mut rbuf).await.unwrap();
            let parsed = Message::from_vec(&rbuf).unwrap();
            assert_eq!(parsed.id(), id);
            assert_eq!(parsed.response_code(), ResponseCode::NoError);
        }

        tcp_task.abort();
        upstream_task.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
