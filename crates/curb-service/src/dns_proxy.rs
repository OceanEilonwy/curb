use std::net::{IpAddr, SocketAddr};

use chrono::Utc;
use curb_core::ipc::BlockedEvent;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::RData;
use tokio::net::UdpSocket;
use tracing::{debug, warn};
use uuid::Uuid;

use crate::engine::ServiceEngine;

/// Async local DNS proxy bound to `127.0.0.1:53` (or a configurable dev port).
///
/// Forwards allowed queries to `upstream`, records returned A/AAAA records into
/// Curb's `DnsCache` with TTLs (feeding per-app WFP IP rules), and returns
/// `REFUSED` for blocked domains.
pub async fn run_dns_proxy(
    engine: ServiceEngine,
    bind_addr: SocketAddr,
    upstream: SocketAddr,
) -> std::io::Result<()> {
    let socket = UdpSocket::bind(bind_addr).await?;
    tracing::info!("Curb local DNS proxy listening on {bind_addr} -> upstream {upstream}");

    let mut buf = [0u8; 4096];
    loop {
        let (len, peer) = socket.recv_from(&mut buf).await?;
        let packet = buf[..len].to_vec();
        let engine = engine.clone();

        let response = handle_dns_packet(&engine, &packet, upstream).await;
        if let Some(resp_bytes) = response {
            if let Err(e) = socket.send_to(&resp_bytes, peer).await {
                warn!("DNS reply send error to {peer}: {e}");
            }
        }
    }
}

async fn handle_dns_packet(
    engine: &ServiceEngine,
    packet: &[u8],
    upstream: SocketAddr,
) -> Option<Vec<u8>> {
    let query = Message::from_vec(packet).ok()?;
    let queried_domain = query
        .queries()
        .first()
        .map(|q| q.name().to_utf8())
        .unwrap_or_default();

    let allowed = {
        let guard = engine.state.lock().unwrap();
        guard.is_dns_query_allowed(&queried_domain)
    };

    if !allowed {
        debug!("DNS blocked: {queried_domain}");
        {
            let mut guard = engine.state.lock().unwrap();
            let clean_domain = queried_domain.trim_end_matches('.').to_string();
            let is_steam_community = clean_domain.contains("steamcommunity.com");
            guard.record_blocked_event(BlockedEvent {
                id: Uuid::new_v4(),
                timestamp: Utc::now(),
                app_name: if is_steam_community {
                    "Steam Community".into()
                } else {
                    "DNS Request".into()
                },
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

    // Forward to upstream resolver
    let upstream_sock = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    upstream_sock.send_to(packet, upstream).await.ok()?;

    let mut resp_buf = [0u8; 4096];
    let resp_len = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        upstream_sock.recv(&mut resp_buf),
    )
    .await
    .ok()?
    .ok()?;

    let resp_bytes = resp_buf[..resp_len].to_vec();

    // Parse A / AAAA records into Curb's TTL cache
    if let Ok(resp_msg) = Message::from_vec(&resp_bytes) {
        let mut ips = Vec::new();
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
                    _ => {}
                }
            }
        }
        if !ips.is_empty() && !queried_domain.is_empty() {
            let ttl = if min_ttl == u32::MAX { 60 } else { min_ttl };
            let mut guard = engine.state.lock().unwrap();
            guard.dns_cache.record(&queried_domain, &ips, ttl);
        }
    }

    Some(resp_bytes)
}
