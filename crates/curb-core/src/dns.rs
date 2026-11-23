use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Normalizes a domain name (lowercase, trims trailing dot and whitespace).
pub fn normalize_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Checks if `domain` matches a Curb whitelist pattern such as
/// `store.steampowered.com` or `*.steamstatic.com`.
///
/// Wildcards (`*.example.com`) match `a.example.com`, `a.b.example.com`,
/// and the apex `example.com` itself.
pub fn domain_matches_pattern(domain: &str, pattern: &str) -> bool {
    let d = normalize_domain(domain);
    let p = normalize_domain(pattern);
    if d.is_empty() || p.is_empty() {
        return false;
    }

    if let Some(suffix) = p.strip_prefix("*.") {
        d == suffix || d.ends_with(&format!(".{suffix}"))
    } else {
        d == p
    }
}

/// Returns true if `domain` matches any pattern in `patterns`.
pub fn domain_matches_any(domain: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|p| domain_matches_pattern(domain, p))
}

#[derive(Debug, Clone)]
struct CachedIp {
    ip: IpAddr,
    expires_at: Instant,
}

/// In-memory TTL cache mapping resolved domains to their A / AAAA records.
/// Used by Curb's local DNS proxy to feed dynamic per-app IP rules into WFP.
#[derive(Debug, Default)]
pub struct DnsCache {
    entries: HashMap<String, Vec<CachedIp>>,
}

impl DnsCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records resolved IPs for `domain` with a minimum TTL floor so short CDN
    /// TTLs don't cause mid-connection drops.
    pub fn record(&mut self, domain: &str, ips: &[IpAddr], ttl_secs: u32) {
        let key = normalize_domain(domain);
        let ttl = Duration::from_secs(ttl_secs.max(30) as u64);
        let now = Instant::now();
        let expires_at = now + ttl;

        let list = self.entries.entry(key).or_default();
        list.retain(|e| e.expires_at > now);

        for &ip in ips {
            if let Some(existing) = list.iter_mut().find(|e| e.ip == ip) {
                existing.expires_at = expires_at;
            } else {
                list.push(CachedIp { ip, expires_at });
            }
        }
    }

    /// Purges expired entries across the cache.
    pub fn prune_expired(&mut self) {
        let now = Instant::now();
        self.entries.retain(|_, list| {
            list.retain(|e| e.expires_at > now);
            !list.is_empty()
        });
    }

    /// Returns all currently valid IPs for domains matching any of `patterns`.
    pub fn allowed_ips_for_patterns(&self, patterns: &[String]) -> Vec<IpAddr> {
        let now = Instant::now();
        let mut set = HashSet::new();

        for (domain, list) in &self.entries {
            if domain_matches_any(domain, patterns) {
                for entry in list {
                    if entry.expires_at > now {
                        set.insert(entry.ip);
                    }
                }
            }
        }

        let mut ips: Vec<IpAddr> = set.into_iter().collect();
        ips.sort();
        ips
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn wildcard_matching_handles_subdomains_and_trailing_dots() {
        assert!(domain_matches_pattern(
            "shared.fastly.steamstatic.com.",
            "*.steamstatic.com"
        ));
        assert!(domain_matches_pattern("steamstatic.com", "*.steamstatic.com"));
        assert!(!domain_matches_pattern("evilsteamstatic.com", "*.steamstatic.com"));
        assert!(domain_matches_pattern(
            "STORE.STEAMPOWERED.COM",
            "store.steampowered.com"
        ));
        assert!(!domain_matches_pattern(
            "evil.store.steampowered.com",
            "store.steampowered.com"
        ));
    }

    #[test]
    fn dns_cache_returns_ips_matching_app_whitelist() {
        let mut cache = DnsCache::new();
        let v4 = IpAddr::V4(Ipv4Addr::new(104, 16, 1, 2));
        let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let other = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        cache.record("cdn.steamstatic.com", &[v4, v6], 60);
        cache.record("youtube.com", &[other], 60);

        let patterns = vec!["*.steamstatic.com".to_string()];
        let allowed = cache.allowed_ips_for_patterns(&patterns);
        assert_eq!(allowed.len(), 2);
        assert!(allowed.contains(&v4));
        assert!(allowed.contains(&v6));
        assert!(!allowed.contains(&other));
    }
}
