use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::config::BaselinePolicy;
use crate::ipc::{BlockedEvent, RunningAppInfo};
use crate::presets::{EffectiveRule, SteamPresetConfig};
use crate::steam::{collect_game_executables, discover_steam_games, DiscoveredSteamGame};
use crate::verify::{inspect_binary, peek_binary, BinaryIdentity};
use crate::Result;

/// Discovers running processes and interactive desktop windows on the host OS.
pub trait ProcessDiscoverer: Send + Sync {
    /// Returns PIDs of processes that currently own a visible GUI window in the
    /// calling user's desktop session.
    fn visible_window_pids(&self) -> Vec<u32>;

    /// Enumerates currently running applications grouped by executable path,
    /// annotating apps that recently attempted to connect online.
    fn collect_running_apps(
        &self,
        recent_blocked: &[BlockedEvent],
        caller_visible_pids: Option<&[u32]>,
    ) -> Vec<RunningAppInfo>;
}

/// Inspects executables for SHA-256 digests, OS signatures, and embedded metadata.
pub trait BinaryVerifier: Send + Sync {
    /// Full verification (computes SHA-256 + OS signature/metadata inspection).
    fn inspect_binary(&self, path: &Path) -> Result<BinaryIdentity>;

    /// Fast metadata-only peek for listing many apps without full-file hashing.
    fn peek_binary(&self, path: &Path) -> Result<BinaryIdentity>;
}

/// Discovers Steam libraries, installed games, and OS-specific Steam preset rules.
pub trait SteamDiscoverer: Send + Sync {
    /// Locates the default Steam installation root on this machine.
    fn find_steam_root(&self) -> Option<PathBuf>;

    /// Scans `steam_root` and all secondary libraries for installed games.
    fn discover_games(&self, steam_root: &Path) -> Result<Vec<DiscoveredSteamGame>>;

    /// Collects all non-ignored game executables inside `game_dir`.
    fn collect_game_executables(&self, game_dir: &Path) -> Vec<PathBuf>;

    /// Returns known Steam client binary paths under `steam_root` for proactive firewall rules.
    fn steam_client_candidate_paths(&self, steam_root: &Path) -> Vec<PathBuf> {
        let _ = steam_root;
        Vec::new()
    }

    /// Expands `SteamPresetConfig` into OS-specific enforcement rules.
    fn expand_steam_preset(&self, preset: &SteamPresetConfig) -> Vec<EffectiveRule> {
        preset.expand_windows_rules()
    }
}

/// Manages the OS-level default-deny firewall (e.g. Windows WFP, Linux nftables).
pub trait FirewallManager: Send + Sync {
    /// Applies or updates default-deny firewall rules for `baseline` and local DNS proxy port.
    fn apply_enforcing(
        &self,
        baseline: &BaselinePolicy,
        dns_proxy_port: u16,
    ) -> std::result::Result<(), String>;

    /// Removes all Curb-owned firewall objects so full network traffic is restored.
    fn purge_all(&self) -> std::result::Result<usize, String>;
}

/// Discovers upstream DNS resolvers and restores system DNS settings on cleanup.
pub trait DnsManager: Send + Sync {
    /// Discovers real upstream DNS resolvers (excluding loopback stubs).
    fn discover_upstreams(&self) -> Vec<SocketAddr>;

    /// Restores original OS/adapter DNS settings cleanly.
    fn restore_clean(&self, data_dir: &Path) -> std::result::Result<(), String>;
}

/// Manages installation and lifecycle of Curb's privileged background daemon
/// (e.g. Windows SCM, Linux `systemd`, or `OpenRC`).
pub trait ServiceManager: Send + Sync {
    /// Installs and starts the system service.
    fn install(
        &self,
        data_dir: &Path,
        service_bin: Option<PathBuf>,
        migrate_from: Option<PathBuf>,
        reset: bool,
    ) -> std::result::Result<(), String>;

    /// Stops and unregisters the system service.
    fn uninstall(&self, data_dir: &Path) -> std::result::Result<(), String>;

    /// Starts the installed system service.
    fn start(&self) -> std::result::Result<(), String>;

    /// Stops the system service if it is currently running.
    fn stop_if_running(&self) -> std::result::Result<(), String>;
}

/// Desktop-environment integration for the unprivileged `curb-app` UI:
/// privilege elevation, login tray autostart, Standard Mode proxy, and data paths.
pub trait DesktopIntegration: Send + Sync {
    /// Triggers a single native admin prompt (UAC / Polkit) to install Curb's service.
    fn launch_elevated_install(&self, migrate_from: &Path) -> std::result::Result<(), String>;

    /// Triggers a single native admin prompt (UAC / Polkit) to uninstall Curb's service.
    fn launch_elevated_uninstall(&self) -> std::result::Result<(), String>;

    /// Registers `curb-app` to start quietly in the system tray on login.
    fn ensure_tray_autostart(&self);

    /// Configures or clears the per-user Standard Mode HTTP proxy in the desktop environment.
    fn set_user_proxy(&self, enable: bool, port: u16);

    /// Default system data directory (`C:\ProgramData\Curb` or `/var/lib/curb`).
    fn system_data_dir(&self) -> PathBuf;

    /// Default per-user Standard Mode data directory.
    fn user_data_dir(&self) -> PathBuf;

    /// Returns `(description, placeholder)` for the "Add Executable by Path" UI prompt.
    fn exe_path_prompt(&self) -> (&'static str, &'static str);
}

/// Composed set of OS/subsystem adaptors injected into `ServiceEngine`.
#[derive(Clone)]
pub struct ServiceAdaptors {
    pub processes: Arc<dyn ProcessDiscoverer>,
    pub verifier: Arc<dyn BinaryVerifier>,
    pub steam: Arc<dyn SteamDiscoverer>,
}

/// Pure-Rust default `BinaryVerifier` (SHA-256 + in-memory cache; no OS signature checks).
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultBinaryVerifier;

impl BinaryVerifier for DefaultBinaryVerifier {
    fn inspect_binary(&self, path: &Path) -> Result<BinaryIdentity> {
        inspect_binary(path)
    }

    fn peek_binary(&self, path: &Path) -> Result<BinaryIdentity> {
        peek_binary(path)
    }
}

/// No-op `ProcessDiscoverer` suitable for unit tests and unsupported targets.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopProcessDiscoverer;

impl ProcessDiscoverer for NoopProcessDiscoverer {
    fn visible_window_pids(&self) -> Vec<u32> {
        Vec::new()
    }

    fn collect_running_apps(
        &self,
        _recent_blocked: &[BlockedEvent],
        _caller_visible_pids: Option<&[u32]>,
    ) -> Vec<RunningAppInfo> {
        Vec::new()
    }
}

/// Pure-Rust `SteamDiscoverer` backed by VDF/ACF parsing (no OS registry lookups).
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultSteamDiscoverer;

impl SteamDiscoverer for DefaultSteamDiscoverer {
    fn find_steam_root(&self) -> Option<PathBuf> {
        None
    }

    fn discover_games(&self, steam_root: &Path) -> Result<Vec<DiscoveredSteamGame>> {
        discover_steam_games(steam_root)
    }

    fn collect_game_executables(&self, game_dir: &Path) -> Vec<PathBuf> {
        collect_game_executables(game_dir)
    }
}

impl Default for ServiceAdaptors {
    fn default() -> Self {
        Self {
            processes: Arc::new(NoopProcessDiscoverer),
            verifier: Arc::new(DefaultBinaryVerifier),
            steam: Arc::new(DefaultSteamDiscoverer),
        }
    }
}
