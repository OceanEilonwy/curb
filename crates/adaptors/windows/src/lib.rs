#[cfg(windows)]
pub mod desktop;
#[cfg(windows)]
pub mod scm;

#[cfg(windows)]
pub use desktop::WindowsDesktopIntegration;
#[cfg(windows)]
pub use scm::WindowsServiceManager;

#[cfg(windows)]
mod core_adaptors {
    use std::net::SocketAddr;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use curb_core::adaptors::{
        BinaryVerifier, DnsManager, FirewallManager, ProcessDiscoverer, ServiceAdaptors,
        SteamDiscoverer,
    };
    use curb_core::config::BaselinePolicy;
    use curb_core::ipc::{BlockedEvent, RunningAppInfo};
    use curb_core::steam::{
        collect_game_executables, discover_steam_games, find_default_steam_root,
        DiscoveredSteamGame,
    };
    use curb_core::verify::{inspect_binary, peek_binary, BinaryIdentity};
    use curb_core::Result;

    /// Windows ToolHelp32 + `EnumWindows` `ProcessDiscoverer`.
    #[derive(Debug, Default, Clone, Copy)]
    pub struct WindowsProcessDiscoverer;

    impl ProcessDiscoverer for WindowsProcessDiscoverer {
        fn visible_window_pids(&self) -> Vec<u32> {
            curb_core::processes::visible_window_pids()
        }

        fn collect_running_apps(
            &self,
            recent_blocked: &[BlockedEvent],
            caller_visible_pids: Option<&[u32]>,
        ) -> Vec<RunningAppInfo> {
            curb_core::processes::collect_running_apps(recent_blocked, caller_visible_pids)
        }
    }

    /// Windows Authenticode (`WinVerifyTrust`) + PE `BinaryVerifier`.
    #[derive(Debug, Default, Clone, Copy)]
    pub struct WindowsBinaryVerifier;

    impl BinaryVerifier for WindowsBinaryVerifier {
        fn inspect_binary(&self, path: &Path) -> Result<BinaryIdentity> {
            inspect_binary(path)
        }

        fn peek_binary(&self, path: &Path) -> Result<BinaryIdentity> {
            peek_binary(path)
        }
    }

    /// Windows Registry + `.exe` `SteamDiscoverer`.
    #[derive(Debug, Default, Clone, Copy)]
    pub struct WindowsSteamDiscoverer;

    impl SteamDiscoverer for WindowsSteamDiscoverer {
        fn find_steam_root(&self) -> Option<PathBuf> {
            find_default_steam_root()
        }

        fn discover_games(&self, steam_root: &Path) -> Result<Vec<DiscoveredSteamGame>> {
            discover_steam_games(steam_root)
        }

        fn collect_game_executables(&self, game_dir: &Path) -> Vec<PathBuf> {
            collect_game_executables(game_dir)
        }
    }

    /// Windows Filtering Platform (WFP) cleanup & management adaptor.
    #[derive(Debug, Default, Clone, Copy)]
    pub struct WindowsFirewallManager;

    impl FirewallManager for WindowsFirewallManager {
        fn apply_enforcing(
            &self,
            _baseline: &BaselinePolicy,
            _dns_proxy_port: u16,
        ) -> std::result::Result<(), String> {
            // Dynamic WFP reconciliation runs inside `curb-service`'s WFP session loop.
            Ok(())
        }

        fn purge_all(&self) -> std::result::Result<usize, String> {
            curb_core::cleanup::purge_all_curb_wfp_objects()
        }
    }

    /// Windows Adapter DNS cleanup adaptor.
    #[derive(Debug, Default, Clone, Copy)]
    pub struct WindowsDnsManager;

    impl DnsManager for WindowsDnsManager {
        fn discover_upstreams(&self) -> Vec<SocketAddr> {
            Vec::new()
        }

        fn restore_clean(&self, data_dir: &Path) -> std::result::Result<(), String> {
            curb_core::cleanup::restore_adapter_dns_clean(data_dir)
        }
    }

    /// Constructs a Windows `ServiceAdaptors` bundle for `ServiceEngine`.
    pub fn service_adaptors() -> ServiceAdaptors {
        ServiceAdaptors {
            processes: Arc::new(WindowsProcessDiscoverer),
            verifier: Arc::new(WindowsBinaryVerifier),
            steam: Arc::new(WindowsSteamDiscoverer),
        }
    }
}

#[cfg(windows)]
pub use core_adaptors::{
    service_adaptors, WindowsBinaryVerifier, WindowsDnsManager, WindowsFirewallManager,
    WindowsProcessDiscoverer, WindowsSteamDiscoverer,
};
