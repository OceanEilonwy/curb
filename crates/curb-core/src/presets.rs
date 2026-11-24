use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::config::{ExecutableMatcher, NetworkPolicy, PresetsConfig, SubprocessPolicy};
use crate::verify::{peek_binary, BinaryIdentity};
use crate::Result;

/// Target operating system passed to preset plugins when expanding OS-specific rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetOs {
    Windows,
    Linux,
    Other,
}

/// Windows registry hive selector used by [`PresetHost::read_windows_registry_string`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryRoot {
    LocalMachine,
    CurrentUser,
}

/// Describes a single user-facing feature toggle belonging to a preset plugin
/// (e.g. Steam's `"community_and_workshop"` or Discord's `"voice_and_calls"`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PresetToggleDescriptor {
    pub key: String,
    pub label: String,
    pub description: String,
    pub default_enabled: bool,
}

/// Metadata describing a registered preset plugin for UI and CLI rendering.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PresetDescriptor {
    pub id: String,
    pub name: String,
    pub description: String,
    pub toggles: Vec<PresetToggleDescriptor>,
}

/// Persisted configuration state for any preset plugin.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PresetState {
    pub enabled: bool,
    /// Per-preset feature toggles keyed by [`PresetToggleDescriptor::key`].
    #[serde(default)]
    pub toggles: BTreeMap<String, bool>,
}

impl PresetState {
    /// Returns the toggle value for `key`, falling back to `default` if unset.
    pub fn toggle(&self, key: &str, default: bool) -> bool {
        self.toggles.get(key).copied().unwrap_or(default)
    }
}

/// A compiled enforcement rule generated from either a user `Rule` or a preset plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveRule {
    pub label: String,
    pub matcher: ExecutableMatcher,
    pub network: NetworkPolicy,
    pub subprocesses: SubprocessPolicy,
}

/// An app or game discovered by a launcher/store preset plugin (Steam, Epic, GOG, etc.).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoveredPresetItem {
    pub preset_id: String,
    pub item_id: String,
    pub name: String,
    pub install_dir: PathBuf,
    pub exe_path: PathBuf,
    pub exe_name: String,
    pub signed: bool,
    pub signer: Option<String>,
    pub sha256: String,
}

/// Hint returned when a preset plugin recognizes a blocked DNS domain as belonging
/// to one of its optional feature toggles (e.g. `steamcommunity.com` -> Steam Community).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockedDomainHint {
    pub preset_id: String,
    pub app_name: String,
    pub toggle_key: Option<String>,
    pub is_steam_community: bool,
}

/// OS-agnostic host services provided to preset plugins so plugins themselves
/// remain 100% pure Rust with zero OS dependencies.
pub trait PresetHost: Send + Sync {
    /// Returns the host operating system.
    fn target_os(&self) -> TargetOs;

    /// Returns true if `path` is an executable binary on this OS (e.g. `.exe` on Windows,
    /// executable ELF or Proton `.exe` on Linux).
    fn is_executable(&self, path: &Path) -> bool;

    /// Fast metadata-only peek of an executable binary.
    fn peek_binary(&self, path: &Path) -> Result<BinaryIdentity>;

    /// Reads a string value from the Windows Registry (`None` on non-Windows hosts).
    fn read_windows_registry_string(
        &self,
        _root: RegistryRoot,
        _subkey: &str,
        _value: &str,
    ) -> Option<String> {
        None
    }

    /// Returns candidate user home directories on this host.
    fn user_home_dirs(&self) -> Vec<PathBuf>;
}

/// Pure-Rust default [`PresetHost`] for unit tests and unsupported OSes.
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultPresetHost {
    pub target: Option<TargetOs>,
}

impl PresetHost for DefaultPresetHost {
    fn target_os(&self) -> TargetOs {
        self.target.unwrap_or(TargetOs::Other)
    }

    fn is_executable(&self, path: &Path) -> bool {
        crate::steam::is_windows_exe(path)
    }

    fn peek_binary(&self, path: &Path) -> Result<BinaryIdentity> {
        peek_binary(path)
    }

    fn user_home_dirs(&self) -> Vec<PathBuf> {
        std::env::var("HOME")
            .ok()
            .map(|h| vec![PathBuf::from(h)])
            .unwrap_or_default()
    }
}

/// Generic plugin interface for built-in or third-party Curb presets
/// (Steam, Epic Games, Discord, Battle.net, Spotify, etc.).
pub trait PresetPlugin: Send + Sync {
    /// Stable unique identifier (e.g. `"steam"`, `"discord"`, `"epic"`).
    fn id(&self) -> &'static str;

    /// Human-readable metadata and toggle schema for UI/CLI rendering.
    fn descriptor(&self) -> PresetDescriptor;

    /// Default initial state for this preset when not yet configured.
    fn default_state(&self) -> PresetState {
        let desc = self.descriptor();
        let toggles = desc
            .toggles
            .into_iter()
            .map(|t| (t.key, t.default_enabled))
            .collect();
        PresetState {
            enabled: false,
            toggles,
        }
    }

    /// Expands this preset's active configuration into firewall/DNS enforcement rules.
    fn expand_rules(&self, state: &PresetState, target: TargetOs) -> Vec<EffectiveRule>;

    /// Returns known on-disk executable paths for proactive 0ms firewall rules.
    fn candidate_paths(&self, _state: &PresetState, _host: &dyn PresetHost) -> Vec<PathBuf> {
        Vec::new()
    }

    /// Discovers launcher-managed apps or games belonging to this preset (optional).
    fn discover_items(&self, _host: &dyn PresetHost) -> Result<Vec<DiscoveredPresetItem>> {
        Ok(Vec::new())
    }

    /// Optionally classifies a blocked DNS domain as belonging to one of this preset's
    /// optional toggles so the UI can surface a helpful label/quick-enable hint.
    fn classify_blocked_domain(&self, _domain: &str) -> Option<BlockedDomainHint> {
        None
    }
}

/// Central registry holding all active [`PresetPlugin`] instances.
#[derive(Default, Clone)]
pub struct PresetRegistry {
    plugins: Vec<Arc<dyn PresetPlugin>>,
}

impl PresetRegistry {
    pub fn new() -> Self {
        Self {
            plugins: Vec::new(),
        }
    }

    /// Registers a preset plugin (replacing any existing plugin with the same `id`).
    pub fn register(&mut self, plugin: Arc<dyn PresetPlugin>) {
        let id = plugin.id();
        self.plugins.retain(|p| p.id() != id);
        self.plugins.push(plugin);
    }

    pub fn get(&self, id: &str) -> Option<&Arc<dyn PresetPlugin>> {
        self.plugins.iter().find(|p| p.id() == id)
    }

    pub fn all(&self) -> &[Arc<dyn PresetPlugin>] {
        &self.plugins
    }

    pub fn descriptors(&self) -> Vec<PresetDescriptor> {
        self.plugins.iter().map(|p| p.descriptor()).collect()
    }

    /// Expands all enabled registered presets into flat [`EffectiveRule`]s.
    pub fn expand_all_rules(&self, config: &PresetsConfig, target: TargetOs) -> Vec<EffectiveRule> {
        let mut out = Vec::new();
        for plugin in &self.plugins {
            let state = config
                .state_for(plugin.id())
                .unwrap_or_else(|| plugin.default_state());
            if state.enabled {
                out.extend(plugin.expand_rules(&state, target));
            }
        }
        out
    }

    /// Collects proactive candidate executable paths from all enabled registered presets.
    pub fn collect_candidate_paths(
        &self,
        config: &PresetsConfig,
        host: &dyn PresetHost,
    ) -> Vec<PathBuf> {
        let mut out = Vec::new();
        for plugin in &self.plugins {
            let state = config
                .state_for(plugin.id())
                .unwrap_or_else(|| plugin.default_state());
            if state.enabled {
                for p in plugin.candidate_paths(&state, host) {
                    if !out.contains(&p) {
                        out.push(p);
                    }
                }
            }
        }
        out
    }

    /// Queries registered presets to classify a blocked DNS domain.
    pub fn classify_blocked_domain(&self, domain: &str) -> Option<BlockedDomainHint> {
        self.plugins
            .iter()
            .find_map(|p| p.classify_blocked_domain(domain))
    }
}

/// Backward-compatible configuration struct for the built-in Steam preset
/// (serialized under `config.presets.steam` in `config.json`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SteamPresetConfig {
    pub enabled: bool,
    /// Allow Store & Library assets in `steamwebhelper` (blocks external links).
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

impl SteamPresetConfig {
    pub const TOGGLE_STORE: &'static str = "store_and_library";
    pub const TOGGLE_COMMUNITY: &'static str = "community_and_workshop";
    pub const TOGGLE_FRIENDS: &'static str = "friends_and_voice";

    /// Converts into generic [`PresetState`] consumed by `SteamPresetPlugin`.
    pub fn to_preset_state(&self) -> PresetState {
        let mut toggles = BTreeMap::new();
        toggles.insert(Self::TOGGLE_STORE.into(), self.store_and_library);
        toggles.insert(Self::TOGGLE_COMMUNITY.into(), self.community_and_workshop);
        toggles.insert(Self::TOGGLE_FRIENDS.into(), self.friends_and_voice);
        PresetState {
            enabled: self.enabled,
            toggles,
        }
    }

    /// Reconstructs `SteamPresetConfig` from generic [`PresetState`].
    pub fn from_preset_state(state: &PresetState) -> Self {
        Self {
            enabled: state.enabled,
            store_and_library: state.toggle(Self::TOGGLE_STORE, true),
            community_and_workshop: state.toggle(Self::TOGGLE_COMMUNITY, false),
            friends_and_voice: state.toggle(Self::TOGGLE_FRIENDS, false),
        }
    }
}
