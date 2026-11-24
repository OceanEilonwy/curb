#[cfg(target_os = "linux")]
pub mod nfqueue;
#[cfg(target_os = "linux")]
pub mod ruleset;

/// Default NFQUEUE number used by Curb's `table inet curb` output filter chain.
pub const CURB_NFQUEUE_NUM: u16 = 42;

#[cfg(target_os = "linux")]
pub use nfqueue::{parse_ip_packet, run_nfqueue_loop, L4Proto, PacketContext, PacketTuple};
#[cfg(target_os = "linux")]
pub use ruleset::{build_ruleset, NftablesFirewall};
