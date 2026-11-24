use serde::{Deserialize, Serialize};

use crate::config::{ExecutableMatcher, NetworkPolicy, SubprocessPolicy};

/// Modular configuration for the built-in Steam preset.
///
/// `steam.exe` and `steamservice.exe` (verified Valve Corp. signatures) are allowed
/// on TCP/UDP whenever the preset is enabled so auth, downloads, cloud saves, and
/// Steam Networking Sockets work reliably. `steamwebhelper.exe` (Steam's embedded
/// Chromium browser) is strictly restricted to the DNS whitelist controlled by the
/// toggles below.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SteamPresetConfig {
    pub enabled: bool,
    /// Allow Store & Library assets in `steamwebhelper.exe` (blocks external links).
    pub store_and_library: bool,
    /// Allow Steam Community & Workshop (`steamcommunity.com`, `*.steamusercontent.com`).
    pub community_and_workshop: bool,
    /// Allow Steam Friends chat & voice endpoints (`*.steam-chat.com`).
    pub friends_and_voice: bool,
}

impl Default for SteamPresetConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            store_and_library: true,
            community_and_workshop: false,
            friends_and_voice: false,
        }
    }
}

/// A compiled enforcement rule generated from either a user `Rule` or a built-in preset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveRule {
    pub label: String,
    pub matcher: ExecutableMatcher,
    pub network: NetworkPolicy,
    pub subprocesses: SubprocessPolicy,
}

pub const VALVE_SIGNER: &str = "Valve Corp.";

pub const STEAM_STORE_DOMAINS: &[&str] = &[
    "store.steampowered.com",
    "checkout.steampowered.com",
    "login.steampowered.com",
    "api.steampowered.com",
    "media.steampowered.com",
    "help.steampowered.com",
    "cmp.steampowered.com",
    "ssa.steampowered.com",
    "*.steampowered.com",
    "partner.steamgames.com",
    "steamgames.com",
    "*.steamgames.com",
    "*.steamstatic.com",
    "*.steamcontent.com",
    "*.steamserver.net",
    "steamcdn-a.akamaihd.net",
    "*.akamaihd.net",
    "*.akamaized.net",
];

pub const STEAM_COMMUNITY_DOMAINS: &[&str] = &[
    "steamcommunity.com",
    "*.steamcommunity.com",
    "*.steamusercontent.com",
];

pub const STEAM_FRIENDS_DOMAINS: &[&str] = &[
    "*.steam-chat.com",
    "steam-chat.com",
    "*.cm.steampowered.com",
    "*.steamserver.net",
];

impl SteamPresetConfig {
    /// Returns the DNS whitelist currently active for `steamwebhelper.exe`.
    pub fn webhelper_domains(&self) -> Vec<String> {
        if !self.enabled {
            return Vec::new();
        }
        let mut domains = Vec::new();
        let mut push_unique = |list: &[&str]| {
            for &item in list {
                if !domains.iter().any(|d: &String| d.eq_ignore_ascii_case(item)) {
                    domains.push(item.to_string());
                }
            }
        };
        if self.store_and_library {
            push_unique(STEAM_STORE_DOMAINS);
        }
        if self.community_and_workshop {
            push_unique(STEAM_COMMUNITY_DOMAINS);
        }
        if self.friends_and_voice {
            push_unique(STEAM_FRIENDS_DOMAINS);
        }
        domains
    }

    /// Expands this preset into concrete enforcement rules.
    pub fn expand_rules(&self) -> Vec<EffectiveRule> {
        if !self.enabled {
            return Vec::new();
        }

        #[cfg(target_os = "linux")]
        let (core_matcher, svc_matcher, web_matcher) = (
            ExecutableMatcher::Path {
                path: "ubuntu12_32/steam".into(),
                filename_hint: "steam".into(),
            },
            ExecutableMatcher::Path {
                path: "steam-runtime-launcher-service".into(),
                filename_hint: "steam-runtime-launcher-service".into(),
            },
            ExecutableMatcher::Path {
                path: "ubuntu12_64/steamwebhelper".into(),
                filename_hint: "steamwebhelper".into(),
            },
        );

        #[cfg(not(target_os = "linux"))]
        let (core_matcher, svc_matcher, web_matcher) = (
            ExecutableMatcher::Signature {
                subject_cn: VALVE_SIGNER.into(),
                issuer_cn: None,
                product_name: None,
                original_filename: Some("steam.exe".into()),
            },
            ExecutableMatcher::Signature {
                subject_cn: VALVE_SIGNER.into(),
                issuer_cn: None,
                product_name: None,
                original_filename: Some("steamservice.exe".into()),
            },
            ExecutableMatcher::Signature {
                subject_cn: VALVE_SIGNER.into(),
                issuer_cn: None,
                product_name: None,
                original_filename: Some("steamwebhelper.exe".into()),
            },
        );

        let mut rules = vec![
            EffectiveRule {
                label: "Steam Client (Core & Downloads)".into(),
                matcher: core_matcher,
                network: NetworkPolicy {
                    allow_tcp: true,
                    allow_udp: true,
                    dns_whitelist: None,
                },
                subprocesses: SubprocessPolicy::Disabled,
            },
            EffectiveRule {
                label: "Steam Client Service".into(),
                matcher: svc_matcher,
                network: NetworkPolicy {
                    allow_tcp: true,
                    allow_udp: true,
                    dns_whitelist: None,
                },
                subprocesses: SubprocessPolicy::Disabled,
            },
        ];

        let web_domains = self.webhelper_domains();
        if !web_domains.is_empty() {
            rules.push(EffectiveRule {
                label: "Steam Web Helper (DNS-restricted)".into(),
                matcher: web_matcher,
                network: NetworkPolicy {
                    allow_tcp: true,
                    // UDP is scoped to `dns_whitelist` IPs (plus LAN SSDP/mDNS for Media
                    // Router/Cast), allowing Chromium HTTP/3 (QUIC) to Steam CDNs without
                    // permitting arbitrary UDP (such as direct DNS to 8.8.4.4:53).
                    allow_udp: true,
                    dns_whitelist: Some(web_domains),
                },
                subprocesses: SubprocessPolicy::Disabled,
            });
        }

        rules
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steam_preset_restricts_webhelper_with_dns_whitelist() {
        let cfg = SteamPresetConfig::default();
        let rules = cfg.expand_rules();
        assert_eq!(rules.len(), 3);

        let web = &rules[2];
        assert!(web.network.allow_tcp);
        assert!(web.network.allow_udp);
        let dns = web.network.dns_whitelist.as_ref().expect("DNS whitelist");
        assert!(dns.iter().any(|d| d == "store.steampowered.com"));
        assert!(dns.iter().any(|d| d == "*.steampowered.com"));
        assert!(dns.iter().any(|d| d == "*.steamserver.net"));
        assert!(dns.iter().any(|d| d == "*.akamaized.net"));
        assert!(!dns.iter().any(|d| d == "steamcommunity.com"));
    }

    #[test]
    fn steam_preset_disabled_produces_no_rules() {
        let cfg = SteamPresetConfig {
            enabled: false,
            ..Default::default()
        };
        assert!(cfg.expand_rules().is_empty());
    }

    #[test]
    fn steam_webhelper_domains_deduplicates_overlapping_entries() {
        let cfg = SteamPresetConfig {
            enabled: true,
            store_and_library: true,
            community_and_workshop: true,
            friends_and_voice: true,
        };
        let domains = cfg.webhelper_domains();
        let steamserver_count = domains
            .iter()
            .filter(|d| d.eq_ignore_ascii_case("*.steamserver.net"))
            .count();
        assert_eq!(steamserver_count, 1);

        let mut unique = std::collections::HashSet::new();
        for d in &domains {
            assert!(
                unique.insert(d.to_ascii_lowercase()),
                "duplicate domain in webhelper_domains: {d}"
            );
        }
    }
}
