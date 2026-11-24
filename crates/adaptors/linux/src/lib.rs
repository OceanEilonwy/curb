#[cfg(target_os = "linux")]
pub mod dns;
#[cfg(target_os = "linux")]
pub mod proc_net;
#[cfg(target_os = "linux")]
pub mod processes;
#[cfg(target_os = "linux")]
pub mod steam;

/// Netfilter `SO_MARK` ("CURB" in ASCII) applied to `curb-service`'s own upstream
/// DNS sockets so they bypass Curb's firewall DNS redirect and packet queue.
pub const CURB_FW_MARK: u32 = 0x4355_5242;

#[cfg(target_os = "linux")]
pub use dns::LinuxDnsManager;
#[cfg(target_os = "linux")]
pub use processes::LinuxProcessDiscoverer;
#[cfg(target_os = "linux")]
pub use steam::LinuxSteamDiscoverer;

/// Returns the default Curb data directory on Linux:
/// `/var/lib/curb` when running as root, or `$XDG_DATA_HOME/curb` / `$HOME/.local/share/curb` otherwise.
#[cfg(target_os = "linux")]
pub fn default_data_dir() -> std::path::PathBuf {
    if unsafe { libc::geteuid() == 0 } {
        return std::path::PathBuf::from(curb_core::store::LINUX_SYSTEM_DATA_DIR);
    }
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        if !xdg.is_empty() {
            return std::path::PathBuf::from(xdg).join("curb");
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        return std::path::PathBuf::from(home).join(".local/share/curb");
    }
    std::path::PathBuf::from("/tmp/curb-data")
}

/// Resolves the preferred Unix IPC socket path on Linux:
/// `/run/curb/ipc.sock` when running as root or when the system socket exists,
/// otherwise `/tmp/curb-ipc.sock`.
#[cfg(target_os = "linux")]
pub fn default_unix_socket_path() -> &'static str {
    let is_root = unsafe { libc::geteuid() == 0 };
    if is_root || std::path::Path::new(curb_core::ipc::LINUX_UNIX_SOCKET_PATH).exists() {
        curb_core::ipc::LINUX_UNIX_SOCKET_PATH
    } else {
        curb_core::ipc::DEV_UNIX_SOCKET_PATH
    }
}

/// Constructs a Linux `ServiceAdaptors` bundle for `ServiceEngine`.
#[cfg(target_os = "linux")]
pub fn service_adaptors() -> curb_core::adaptors::ServiceAdaptors {
    use std::sync::Arc;
    curb_core::adaptors::ServiceAdaptors {
        processes: Arc::new(LinuxProcessDiscoverer),
        verifier: Arc::new(curb_core::adaptors::DefaultBinaryVerifier),
        steam: Arc::new(LinuxSteamDiscoverer),
    }
}
