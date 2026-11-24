use serde::{Deserialize, Serialize};

/// Stable Curb WFP Provider GUID (u128 representation so it's usable cross-platform).
pub const CURB_PROVIDER_UUID: u128 = 0x7c8e94b1_4412_4f68_a13b_2210c8894e01;

/// Stable Curb WFP Sublayer GUID.
pub const CURB_SUBLAYER_UUID: u128 = 0x7c8e94b1_4412_4f68_a13b_2210c8894e02;

/// Snapshot of a network adapter's original DNS settings saved in
/// `dns_backup.json` before Curb redirects adapter DNS to loopback.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterDnsBackup {
    pub interface_alias: String,
    pub interface_index: u32,
    pub original_servers: Vec<String>,
    #[serde(default)]
    pub v4_static: bool,
    #[serde(default)]
    pub v6_static: bool,
}
