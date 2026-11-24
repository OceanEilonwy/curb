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
