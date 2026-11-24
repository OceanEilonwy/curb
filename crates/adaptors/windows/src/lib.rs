#[cfg(windows)]
pub mod desktop;
#[cfg(windows)]
pub mod dns;
#[cfg(windows)]
pub mod firewall;
#[cfg(windows)]
pub mod processes;
#[cfg(windows)]
pub mod scm;
#[cfg(windows)]
pub mod steam;
#[cfg(windows)]
pub mod verify;

#[cfg(windows)]
pub use desktop::WindowsDesktopIntegration;
#[cfg(windows)]
pub use dns::{restore_adapter_dns_clean, WindowsDnsManager};
#[cfg(windows)]
pub use firewall::{purge_all_curb_wfp_objects, WindowsFirewallManager};
#[cfg(windows)]
pub use processes::WindowsProcessDiscoverer;
#[cfg(windows)]
pub use scm::WindowsServiceManager;
#[cfg(windows)]
pub use steam::WindowsSteamDiscoverer;
#[cfg(windows)]
pub use verify::WindowsBinaryVerifier;

/// Returns the default Curb system data directory on Windows (`%ProgramData%\Curb`).
#[cfg(windows)]
pub fn default_data_dir() -> std::path::PathBuf {
    if let Ok(program_data) = std::env::var("ProgramData") {
        return std::path::PathBuf::from(program_data).join("Curb");
    }
    std::path::PathBuf::from(curb_core::store::WINDOWS_SYSTEM_DATA_DIR)
}

/// Constructs a Windows `ServiceAdaptors` bundle for `ServiceEngine`.
#[cfg(windows)]
pub fn service_adaptors() -> curb_core::adaptors::ServiceAdaptors {
    use std::sync::Arc;
    curb_core::adaptors::ServiceAdaptors {
        processes: Arc::new(WindowsProcessDiscoverer),
        verifier: Arc::new(WindowsBinaryVerifier),
        steam: Arc::new(WindowsSteamDiscoverer),
    }
}
