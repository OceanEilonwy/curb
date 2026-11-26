use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Linux NetworkManager / ConnMan / desktop connectivity-check probe domains
/// across common distributions (Arch/CachyOS/EndeavourOS, Manjaro, Fedora,
/// Ubuntu/Pop!_OS/Mint, Debian, openSUSE, GNOME, KDE, ConnMan, Firefox/Chromium).
pub const LINUX_CONNECTIVITY_DOMAINS: &[&str] = &[
    "ping.archlinux.org",
    "ping.manjaro.org",
    "fedoraproject.org",
    "connectivity-check.ubuntu.com",
    "network.debian.org",
    "conncheck.opensuse.org",
    "nmcheck.gnome.org",
    "networkcheck.kde.org",
    "ipv4.connman.net",
    "ipv6.connman.net",
    "detectportal.firefox.com",
    "connectivitycheck.gstatic.com",
];

/// OS connectivity-check probe domains (Windows NCSI + Linux NetworkManager/ConnMan)
/// used to keep Wi-Fi / Ethernet adapters from showing "No Internet" or "Limited".
pub const NCSI_DOMAINS: &[&str] = &[
    // Windows NCSI
    "www.msftconnecttest.com",
    "ipv6.msftconnecttest.com",
    "dns.msftncsi.com",
    "www.msftncsi.com",
    "ipv6.msftncsi.com",
    // Linux NetworkManager / ConnMan / desktop connectivity checks
    "ping.archlinux.org",
    "ping.manjaro.org",
    "fedoraproject.org",
    "connectivity-check.ubuntu.com",
    "network.debian.org",
    "conncheck.opensuse.org",
    "nmcheck.gnome.org",
    "networkcheck.kde.org",
    "ipv4.connman.net",
    "ipv6.connman.net",
    "detectportal.firefox.com",
    "connectivitycheck.gstatic.com",
];

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
/// Used by Curb's local DNS proxy to feed dynamic per-app IP rules into WFP
/// and annotate blocked connection events with their queried domain name.
#[derive(Debug, Default)]
pub struct DnsCache {
    entries: HashMap<String, Vec<CachedIp>>,
    ip_to_domain: HashMap<IpAddr, String>,
    cname_to_origin: HashMap<String, String>,
    version: u64,
}

const MAX_AUX_CACHE_ENTRIES: usize = 8192;

impl DnsCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Monotonically increasing counter bumped whenever the set of cached IPs changes.
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Associates a CNAME target (`alias`) with the originally queried domain (`origin`)
    /// so follow-up A/AAAA queries directly for the CNAME target inherit the origin domain's
    /// whitelist status and populate its WFP IP set.
    pub fn record_cname(&mut self, alias: &str, origin: &str) {
        let a = normalize_domain(alias);
        let o = normalize_domain(origin);
        if a.is_empty() || o.is_empty() || a == o {
            return;
        }
        let root_origin = self.cname_to_origin.get(&o).cloned().unwrap_or(o);
        if self.cname_to_origin.len() >= MAX_AUX_CACHE_ENTRIES
            && !self.cname_to_origin.contains_key(&a)
        {
            self.cname_to_origin.clear();
        }
        self.cname_to_origin.insert(a, root_origin);
    }

    /// If `domain` was previously observed as a CNAME target of another queried domain,
    /// returns that original domain name.
    pub fn origin_for_domain(&self, domain: &str) -> Option<String> {
        let key = normalize_domain(domain);
        self.cname_to_origin.get(&key).cloned()
    }

    /// Records resolved IPs for `domain` with a minimum TTL floor so short CDN
    /// TTLs don't cause mid-connection drops. Returns `true` if any new IP was added
    /// or an expired entry was removed (indicating WFP IP filters may need updating).
    pub fn record(&mut self, domain: &str, ips: &[IpAddr], ttl_secs: u32) -> bool {
        let key = normalize_domain(domain);
        if key.is_empty() {
            return false;
        }
        let origin = self.cname_to_origin.get(&key).cloned();
        let mut changed = self.record_single_key(&key, ips, ttl_secs);
        if let Some(orig) = origin {
            if orig != key {
                changed |= self.record_single_key(&orig, ips, ttl_secs);
            }
        }
        changed
    }

    fn record_single_key(&mut self, key: &str, ips: &[IpAddr], ttl_secs: u32) -> bool {
        let ttl = Duration::from_secs(ttl_secs.max(300) as u64);
        let now = Instant::now();
        let expires_at = now + ttl;

        let list = self.entries.entry(key.to_string()).or_default();
        let before = list.len();
        list.retain(|e| e.expires_at > now);
        let mut changed = list.len() != before;

        for &ip in ips {
            if self.ip_to_domain.len() >= MAX_AUX_CACHE_ENTRIES
                && !self.ip_to_domain.contains_key(&ip)
            {
                self.ip_to_domain.clear();
            }
            self.ip_to_domain.insert(ip, key.to_string());
            if let Some(existing) = list.iter_mut().find(|e| e.ip == ip) {
                existing.expires_at = expires_at;
            } else {
                list.push(CachedIp { ip, expires_at });
                changed = true;
            }
        }

        if changed {
            self.version = self.version.wrapping_add(1);
        }
        changed
    }

    /// Looks up the most recently resolved domain name associated with `ip`.
    pub fn domain_for_ip(&self, ip: IpAddr) -> Option<String> {
        self.ip_to_domain.get(&ip).cloned()
    }

    /// Purges expired entries across the cache. Returns `true` if any entries expired.
    pub fn prune_expired(&mut self) -> bool {
        let now = Instant::now();
        let mut changed = false;
        self.entries.retain(|_, list| {
            let before = list.len();
            list.retain(|e| e.expires_at > now);
            if list.len() != before {
                changed = true;
            }
            !list.is_empty()
        });
        if changed {
            self.version = self.version.wrapping_add(1);
        }
        changed
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

    #[test]
    fn dns_cache_enforces_ttl_floor_and_bounds_auxiliary_maps() {
        let mut cache = DnsCache::new();
        let zero_ttl_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));

        // Even with ttl_secs = 0, the 300s minimum TTL floor keeps the IP valid.
        assert!(cache.record("store.steampowered.com", &[zero_ttl_ip], 0));
        assert!(!cache.prune_expired());
        assert_eq!(
            cache.allowed_ips_for_patterns(&["store.steampowered.com".to_string()]),
            vec![zero_ttl_ip]
        );

        // Filling ip_to_domain and cname_to_origin beyond MAX_AUX_CACHE_ENTRIES stays bounded.
        for i in 0..(MAX_AUX_CACHE_ENTRIES + 50) {
            let ip = IpAddr::V4(Ipv4Addr::from(0x0A00_0000u32 + i as u32));
            cache.record(&format!("h{i}.steamstatic.com"), &[ip], 60);
            cache.record_cname(&format!("alias{i}.cdn.net"), "store.steampowered.com");
        }
        assert!(cache.ip_to_domain.len() <= MAX_AUX_CACHE_ENTRIES);
        assert!(cache.cname_to_origin.len() <= MAX_AUX_CACHE_ENTRIES);

        let last_ip = IpAddr::V4(Ipv4Addr::from(
            0x0A00_0000u32 + (MAX_AUX_CACHE_ENTRIES + 49) as u32,
        ));
        assert!(cache.domain_for_ip(last_ip).is_some());
        assert_eq!(
            cache.origin_for_domain(&format!("alias{}.cdn.net", MAX_AUX_CACHE_ENTRIES + 49)),
            Some("store.steampowered.com".to_string())
        );
    }
}
