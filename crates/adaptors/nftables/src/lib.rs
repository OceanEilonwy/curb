#[cfg(target_os = "linux")]
pub mod nfqueue;
#[cfg(target_os = "linux")]
pub mod ruleset;

/// Default NFQUEUE number used by Curb's `table inet curb` output filter chain.
pub const CURB_NFQUEUE_NUM: u16 = 42;

#[cfg(target_os = "linux")]
pub use nfqueue::{
    parse_ip_packet, run_nfqueue_loop, run_nfqueue_loop_with_ready, L4Proto, NfqueueVerdict,
    PacketContext, PacketTuple,
};
#[cfg(target_os = "linux")]
pub use ruleset::{
    build_ruleset, build_ruleset_with_options, merge_policy_mark, policy_mark_for_generation,
    NftablesFirewall, RulesetOptions, CURB_POLICY_MARK_CLEAR, CURB_POLICY_MARK_MASK,
};
