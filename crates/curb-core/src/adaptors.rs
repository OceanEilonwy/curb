use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::config::BaselinePolicy;
use crate::ipc::{BlockedEvent, RunningAppInfo};
use crate::presets::{DefaultPresetHost, PresetHost};
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

/// Request describing an application whose native OS icon should be resolved.
#[derive(Debug, Clone, Default)]
pub struct AppIconRequest<'a> {
    /// Full path to the executable binary, if known (e.g. `C:\...\app.exe` or `/usr/bin/firefox`).
    pub exe_path: Option<&'a Path>,
    /// Executable filename or hint (e.g. `firefox.exe`, `discord`, `steam`).
    pub exe_name: Option<&'a str>,
    /// Human-friendly display name (e.g. `"Mozilla Firefox"`, `"Steam"`).
    pub app_name: Option<&'a str>,
    /// Optional Steam AppID (helps locate `steam_icon_<app_id>` or Steam library cache icons).
    pub steam_app_id: Option<u32>,
}

/// Resolved native application icon returned by [`DesktopIntegration::resolve_app_icon`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppIcon {
    /// Decoded straight-alpha RGBA8 pixel buffer (e.g. extracted from a Windows PE `HICON`).
    Rgba {
        width: u32,
        height: u32,
        data: Vec<u8>,
    },
    /// Path to an on-disk icon image file (e.g. `.png` or `.svg` from an XDG icon theme).
    Path(PathBuf),
}

/// Desktop-environment integration for the unprivileged `curb-app` UI:
/// privilege elevation, login tray autostart, Standard Mode proxy, app icons, and data paths.
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

    /// Resolves a small native application icon the same way the host OS process monitor does
    /// (Windows Task Manager PE/Shell icons, KDE System Monitor / GNOME `.desktop` + XDG Icon Theme).
    /// Returns `None` if no native icon is found so the UI can fall back to an avatar badge.
    fn resolve_app_icon(&self, _req: &AppIconRequest<'_>) -> Option<AppIcon> {
        None
    }
}

/// Composed set of OS/subsystem adaptors injected into `ServiceEngine`.
#[derive(Clone)]
pub struct ServiceAdaptors {
    pub processes: Arc<dyn ProcessDiscoverer>,
    pub verifier: Arc<dyn BinaryVerifier>,
    pub preset_host: Arc<dyn PresetHost>,
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

impl Default for ServiceAdaptors {
    fn default() -> Self {
        Self {
            processes: Arc::new(NoopProcessDiscoverer),
            verifier: Arc::new(DefaultBinaryVerifier),
            preset_host: Arc::new(DefaultPresetHost::default()),
        }
    }
}
