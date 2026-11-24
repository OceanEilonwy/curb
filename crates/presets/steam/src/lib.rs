use std::collections::BTreeMap;
use std::path::PathBuf;

use curb_core::config::{ExecutableMatcher, NetworkPolicy, SubprocessPolicy};
use curb_core::presets::{
    BlockedDomainHint, DiscoveredPresetItem, EffectiveRule, PresetDescriptor, PresetHost,
    PresetPlugin, PresetState, PresetToggleDescriptor, RegistryRoot, SteamPresetConfig, TargetOs,
};
use curb_core::steam::{discover_steam_games_with, DiscoveredSteamGame};
use curb_core::Result;

pub const STEAM_PRESET_ID: &str = "steam";
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

/// Built-in Curb preset plugin for Steam.
///
/// Allows Steam's core client binaries on TCP/UDP for login, game downloads, cloud saves,
/// and Steam Networking Sockets, while strictly locking Steam's embedded Chromium browser
/// (`steamwebhelper`) to a DNS whitelist controlled by modular toggles.
#[derive(Debug, Default, Clone, Copy)]
pub struct SteamPresetPlugin;

impl SteamPresetPlugin {
    /// Returns the deduplicated DNS whitelist active for `steamwebhelper` under `state`.
    pub fn webhelper_domains(state: &PresetState) -> Vec<String> {
        if !state.enabled {
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
        if state.toggle(SteamPresetConfig::TOGGLE_STORE, true) {
            push_unique(STEAM_STORE_DOMAINS);
        }
        if state.toggle(SteamPresetConfig::TOGGLE_COMMUNITY, false) {
            push_unique(STEAM_COMMUNITY_DOMAINS);
        }
        if state.toggle(SteamPresetConfig::TOGGLE_FRIENDS, false) {
            push_unique(STEAM_FRIENDS_DOMAINS);
        }
        domains
    }

    /// Locates the Steam installation root using OS-agnostic [`PresetHost`] queries.
    pub fn find_steam_root(host: &dyn PresetHost) -> Option<PathBuf> {
        match host.target_os() {
            TargetOs::Windows => {
                for (root, subkey, value) in [
                    (
                        RegistryRoot::LocalMachine,
                        r"SOFTWARE\WOW6432Node\Valve\Steam",
                        "InstallPath",
                    ),
                    (
                        RegistryRoot::CurrentUser,
                        r"Software\Valve\Steam",
                        "SteamPath",
                    ),
                ] {
                    if let Some(raw) = host.read_windows_registry_string(root, subkey, value) {
                        let p = PathBuf::from(raw.replace('/', "\\"));
                        if p.exists() {
                            return Some(p);
                        }
                    }
                }
                let default = PathBuf::from(r"C:\Program Files (x86)\Steam");
                if default.exists() {
                    return Some(default);
                }
                None
            }
            TargetOs::Linux | TargetOs::Other => {
                for home in host.user_home_dirs() {
                    for rel in [
                        ".local/share/Steam",
                        ".steam/steam",
                        ".steam/debian-installation",
                        ".var/app/com.valvesoftware.Steam/.local/share/Steam",
                        "snap/steam/common/.local/share/Steam",
                    ] {
                        let candidate = home.join(rel);
                        if candidate.join("steamapps").exists() {
                            return Some(candidate);
                        }
                    }
                }
                None
            }
        }
    }

    /// Converts a generic [`DiscoveredPresetItem`] back into [`DiscoveredSteamGame`]
    /// for backward-compatible IPC responses.
    pub fn to_discovered_steam_game(item: DiscoveredPresetItem) -> Option<DiscoveredSteamGame> {
        Some(DiscoveredSteamGame {
            app_id: item.item_id.parse::<u32>().ok()?,
            name: item.name,
            install_dir: item.install_dir,
            exe_path: item.exe_path,
            exe_name: item.exe_name,
            signed: item.signed,
            signer: item.signer,
            sha256: item.sha256,
        })
    }
}

impl PresetPlugin for SteamPresetPlugin {
    fn id(&self) -> &'static str {
        STEAM_PRESET_ID
    }

    fn descriptor(&self) -> PresetDescriptor {
        PresetDescriptor {
            id: STEAM_PRESET_ID.into(),
            name: "Steam".into(),
            description: "Allows Steam downloads & multiplayer while locking Steam's built-in browser to a DNS whitelist.".into(),
            toggles: vec![
                PresetToggleDescriptor {
                    key: SteamPresetConfig::TOGGLE_STORE.into(),
                    label: "Store & Library".into(),
                    description: "Allow Steam Store, Checkout, and Library assets inside Steam.".into(),
                    default_enabled: true,
                },
                PresetToggleDescriptor {
                    key: SteamPresetConfig::TOGGLE_COMMUNITY.into(),
                    label: "Community & Workshop".into(),
                    description: "Allow Steam Community hubs, discussions, and Workshop mods.".into(),
                    default_enabled: false,
                },
                PresetToggleDescriptor {
                    key: SteamPresetConfig::TOGGLE_FRIENDS.into(),
                    label: "Friends & Voice".into(),
                    description: "Allow Steam Friends chat and voice endpoints.".into(),
                    default_enabled: false,
                },
            ],
        }
    }

    fn default_state(&self) -> PresetState {
        let mut toggles = BTreeMap::new();
        toggles.insert(SteamPresetConfig::TOGGLE_STORE.into(), true);
        toggles.insert(SteamPresetConfig::TOGGLE_COMMUNITY.into(), false);
        toggles.insert(SteamPresetConfig::TOGGLE_FRIENDS.into(), false);
        PresetState {
            enabled: true,
            toggles,
        }
    }

    fn expand_rules(&self, state: &PresetState, target: TargetOs) -> Vec<EffectiveRule> {
        if !state.enabled {
            return Vec::new();
        }

        let (core_matcher, svc_matcher, web_matcher) = match target {
            TargetOs::Linux => (
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
            ),
            TargetOs::Windows | TargetOs::Other => (
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
            ),
        };

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

        let web_domains = Self::webhelper_domains(state);
        if !web_domains.is_empty() {
            rules.push(EffectiveRule {
                label: "Steam Web Helper (DNS-restricted)".into(),
                matcher: web_matcher,
                network: NetworkPolicy {
                    allow_tcp: true,
                    allow_udp: true,
                    dns_whitelist: Some(web_domains),
                },
                subprocesses: SubprocessPolicy::Disabled,
            });
        }

        rules
    }

    fn candidate_paths(&self, state: &PresetState, host: &dyn PresetHost) -> Vec<PathBuf> {
        if !state.enabled {
            return Vec::new();
        }
        let Some(root) = Self::find_steam_root(host) else {
            return Vec::new();
        };
        let rels: &[&str] = match host.target_os() {
            TargetOs::Linux => &["ubuntu12_32/steam", "ubuntu12_64/steamwebhelper"],
            TargetOs::Windows | TargetOs::Other => &[
                "steam.exe",
                r"bin\steamservice.exe",
                r"bin\cef\cef.win7x64\steamwebhelper.exe",
                r"bin\cef\steamwebhelper.exe",
            ],
        };
        rels.iter()
            .map(|rel| root.join(rel))
            .filter(|p| p.exists())
            .collect()
    }

    fn discover_items(&self, host: &dyn PresetHost) -> Result<Vec<DiscoveredPresetItem>> {
        let Some(root) = Self::find_steam_root(host) else {
            return Ok(Vec::new());
        };
        let games = discover_steam_games_with(
            &root,
            |p| host.is_executable(p),
            |p| host.peek_binary(p),
        )?;
        Ok(games
            .into_iter()
            .map(|g| DiscoveredPresetItem {
                preset_id: STEAM_PRESET_ID.into(),
                item_id: g.app_id.to_string(),
                name: g.name,
                install_dir: g.install_dir,
                exe_path: g.exe_path,
                exe_name: g.exe_name,
                signed: g.signed,
                signer: g.signer,
                sha256: g.sha256,
            })
            .collect())
    }

    fn classify_blocked_domain(&self, domain: &str) -> Option<BlockedDomainHint> {
        let lower = domain.trim_end_matches('.').to_ascii_lowercase();
        if lower == "steamcommunity.com" || lower.ends_with(".steamcommunity.com") {
            return Some(BlockedDomainHint {
                preset_id: STEAM_PRESET_ID.into(),
                app_name: "Steam Community".into(),
                toggle_key: Some(SteamPresetConfig::TOGGLE_COMMUNITY.into()),
                is_steam_community: true,
            });
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steam_plugin_restricts_webhelper_with_dns_whitelist_on_windows_and_linux() {
        let plugin = SteamPresetPlugin;
        let state = plugin.default_state();
        for target in [TargetOs::Windows, TargetOs::Linux] {
            let rules = plugin.expand_rules(&state, target);
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
    }

    #[test]
    fn steam_plugin_disabled_produces_no_rules() {
        let plugin = SteamPresetPlugin;
        let state = PresetState {
            enabled: false,
            toggles: BTreeMap::new(),
        };
        assert!(plugin.expand_rules(&state, TargetOs::Windows).is_empty());
        assert!(plugin.expand_rules(&state, TargetOs::Linux).is_empty());
    }

    #[test]
    fn steam_webhelper_domains_deduplicates_overlapping_entries() {
        let mut toggles = BTreeMap::new();
        toggles.insert(SteamPresetConfig::TOGGLE_STORE.into(), true);
        toggles.insert(SteamPresetConfig::TOGGLE_COMMUNITY.into(), true);
        toggles.insert(SteamPresetConfig::TOGGLE_FRIENDS.into(), true);
        let state = PresetState {
            enabled: true,
            toggles,
        };
        let domains = SteamPresetPlugin::webhelper_domains(&state);
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

    #[test]
    fn classifies_steam_community_blocked_domains() {
        let plugin = SteamPresetPlugin;
        let hint = plugin
            .classify_blocked_domain("steamcommunity.com.")
            .expect("hint");
        assert_eq!(hint.preset_id, "steam");
        assert_eq!(hint.app_name, "Steam Community");
        assert!(hint.is_steam_community);
        assert!(plugin.classify_blocked_domain("example.com").is_none());
    }
}
