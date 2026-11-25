use std::io::Write;
use std::process::{Command, Stdio};

use curb_core::adaptors::FirewallManager;
use curb_core::config::BaselinePolicy;
use curb_linux::CURB_FW_MARK;

use crate::CURB_NFQUEUE_NUM;

/// Bitmask reserving the top 8 bits of `skb->mark` / `ct->mark` for Curb's policy
/// generation counter while preserving the lower 24 bits used by VPNs and policy
/// routing (`wg-quick`, Tailscale, Mullvad, etc.).
pub const CURB_POLICY_MARK_MASK: u32 = 0xFF00_0000;
/// Inverse mask used to clear only Curb's policy bits from `meta mark` / `ct mark`.
pub const CURB_POLICY_MARK_CLEAR: u32 = !CURB_POLICY_MARK_MASK;

/// Computes a non-zero masked `ct mark` value in the top 8 bits (`0x0100_0000..=0xFE00_0000`),
/// skipping `0x43` so it can never overlap with `CURB_FW_MARK` (`0x4355_5242`).
pub fn policy_mark_for_generation(generation: u64) -> u32 {
    let mut slot = ((generation % 253) as u32) + 1;
    if slot >= 0x43 {
        slot += 1;
    }
    slot << 24
}

/// Merges Curb's top-8-bit `policy_mark` into an existing packet `skb->mark`
/// without clobbering lower 24-bit VPN/routing marks.
pub fn merge_policy_mark(existing_mark: u32, policy_mark: u32) -> u32 {
    (existing_mark & CURB_POLICY_MARK_CLEAR) | (policy_mark & CURB_POLICY_MARK_MASK)
}

/// Parameters controlling Curb's generated `table inet curb` nftables ruleset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RulesetOptions {
    pub dns_proxy_port: u16,
    pub redirect_ipv6: bool,
    pub queue_num: u16,
    pub fw_mark: u32,
    pub policy_ct_mark: u32,
}

/// Linux `nftables` + `NFQUEUE` implementation of [`FirewallManager`].
#[derive(Debug, Default, Clone, Copy)]
pub struct NftablesFirewall;

impl NftablesFirewall {
    /// Applies `table inet curb` with explicit IPv6 redirect and policy-generation
    /// `ct mark` options.
    pub fn apply_enforcing_with_options(
        &self,
        baseline: &BaselinePolicy,
        opts: RulesetOptions,
    ) -> Result<(), String> {
        let script = build_ruleset_with_options(baseline, opts);
        let mut child = Command::new("nft")
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("Failed to spawn `nft` (is nftables installed?): {e}"))?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(script.as_bytes())
                .map_err(|e| format!("Failed writing ruleset to `nft`: {e}"))?;
        }

        let output = child
            .wait_with_output()
            .map_err(|e| format!("Failed waiting for `nft`: {e}"))?;

        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!("`nft -f -` failed: {}", stderr.trim()))
        }
    }

    /// Returns `true` if `table inet curb` is currently present in the kernel.
    /// Used to detect external flushes by `nftables.service`, `firewalld`, or `ufw`.
    pub fn is_applied(&self) -> bool {
        Command::new("nft")
            .args(["list", "table", "inet", "curb"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

impl FirewallManager for NftablesFirewall {
    fn apply_enforcing(
        &self,
        baseline: &BaselinePolicy,
        dns_proxy_port: u16,
    ) -> Result<(), String> {
        self.apply_enforcing_with_options(
            baseline,
            RulesetOptions {
                dns_proxy_port,
                redirect_ipv6: true,
                queue_num: CURB_NFQUEUE_NUM,
                fw_mark: CURB_FW_MARK,
                policy_ct_mark: policy_mark_for_generation(0),
            },
        )
    }

    fn purge_all(&self) -> Result<usize, String> {
        let check = Command::new("nft")
            .args(["list", "table", "inet", "curb"])
            .output();

        let Ok(out) = check else {
            return Ok(0);
        };
        if !out.status.success() {
            return Ok(0);
        }

        let del = Command::new("nft")
            .args(["delete", "table", "inet", "curb"])
            .output()
            .map_err(|e| format!("Failed to invoke nft: {e}"))?;

        if del.status.success() {
            Ok(1)
        } else {
            let stderr = String::from_utf8_lossy(&del.stderr);
            Err(format!("nft delete table inet curb failed: {}", stderr.trim()))
        }
    }
}

/// Builds an atomic `nft -f -` ruleset for `table inet curb` enforcing
/// default-deny outbound TCP/UDP via NFQUEUE while transparently redirecting
/// all non-Curb DNS (UDP/TCP port 53) to Curb's local DNS proxy port.
pub fn build_ruleset(
    baseline: &BaselinePolicy,
    dns_proxy_port: u16,
    queue_num: u16,
    fw_mark: u32,
) -> String {
    build_ruleset_with_options(
        baseline,
        RulesetOptions {
            dns_proxy_port,
            redirect_ipv6: true,
            queue_num,
            fw_mark,
            policy_ct_mark: policy_mark_for_generation(0),
        },
    )
}

/// Builds an atomic `nft -f -` ruleset with explicit IPv6 redirect and
/// conntrack policy-generation marking.
pub fn build_ruleset_with_options(baseline: &BaselinePolicy, opts: RulesetOptions) -> String {
    let RulesetOptions {
        dns_proxy_port,
        redirect_ipv6,
        queue_num,
        fw_mark,
        policy_ct_mark,
    } = opts;
    let masked_policy = policy_ct_mark & CURB_POLICY_MARK_MASK;

    let mut rules = String::new();
    rules.push_str("table inet curb\n");
    rules.push_str("delete table inet curb\n");
    rules.push_str("table inet curb {\n");

    rules.push_str("    chain output {\n");
    rules.push_str("        type filter hook output priority 0; policy accept;\n");
    // Curb's own upstream DNS sockets bypass filtering first.
    rules.push_str(&format!("        meta mark 0x{fw_mark:08x} accept\n"));
    // Packets approved by NFQUEUE are re-injected with `NF_REPEAT` + `NFQA_MARK`
    // carrying Curb's policy generation in the top 8 bits. Stamp only the top 8 bits
    // of `ct mark` and clear only Curb's top 8 bits from `meta mark` so lower 24-bit
    // VPN / policy-routing marks (Tailscale, wg-quick, Mullvad) are preserved intact.
    rules.push_str(&format!(
        "        meta mark & 0x{CURB_POLICY_MARK_MASK:08x} == 0x{masked_policy:08x} ct mark set ct mark & 0x{CURB_POLICY_MARK_CLEAR:08x} | 0x{masked_policy:08x} meta mark set meta mark & 0x{CURB_POLICY_MARK_CLEAR:08x} accept\n"
    ));
    if baseline.loopback {
        rules.push_str("        oifname \"lo\" accept\n");
    } else {
        // Even when general loopback is disabled, redirected DNS traffic to/from
        // Curb's local DNS proxy port on `lo` must always be allowed.
        rules.push_str(&format!(
            "        oifname \"lo\" meta l4proto {{ tcp, udp }} th dport {dns_proxy_port} accept\n"
        ));
        rules.push_str(&format!(
            "        oifname \"lo\" meta l4proto {{ tcp, udp }} th sport {dns_proxy_port} accept\n"
        ));
    }
    if baseline.dhcp {
        rules.push_str("        udp dport { 67, 68, 546, 547 } accept\n");
    }
    if baseline.ntp {
        rules.push_str("        udp dport 123 accept\n");
    }
    // Use `reject` (not `drop`) on DoT port 853 and fallback port 53 so `systemd-resolved`
    // (opportunistic DoT) and IPv6 DNS (when IPv6 proxy is unavailable) fail over immediately.
    rules.push_str("        meta l4proto { tcp, udp } th dport 853 reject\n");
    rules.push_str("        meta l4proto { tcp, udp } th dport 53 reject\n");
    rules.push_str("        meta l4proto { tcp, udp } ct state invalid drop\n");
    // Fast-path all valid packets (including subsequent `ct state new` packets in a
    // QUIC/UDP burst before the first reply) whose conntrack entry was stamped under
    // the current policy generation.
    rules.push_str(&format!(
        "        ct mark & 0x{CURB_POLICY_MARK_MASK:08x} == 0x{masked_policy:08x} accept\n"
    ));
    rules.push_str(&format!(
        "        meta l4proto {{ tcp, udp }} queue num {queue_num}\n"
    ));
    rules.push_str("    }\n");

    rules.push_str("    chain nat_output {\n");
    rules.push_str("        type nat hook output priority -100; policy accept;\n");
    rules.push_str(&format!("        meta mark 0x{fw_mark:08x} return\n"));
    // Separate `tcp` and `udp` rules are required by nftables for port-mapping `redirect to :port`.
    if redirect_ipv6 {
        rules.push_str(&format!(
            "        tcp dport 53 redirect to :{dns_proxy_port}\n"
        ));
        rules.push_str(&format!(
            "        udp dport 53 redirect to :{dns_proxy_port}\n"
        ));
    } else {
        rules.push_str(&format!(
            "        meta nfproto ipv4 tcp dport 53 redirect to :{dns_proxy_port}\n"
        ));
        rules.push_str(&format!(
            "        meta nfproto ipv4 udp dport 53 redirect to :{dns_proxy_port}\n"
        ));
    }
    rules.push_str("    }\n");

    rules.push_str("}\n");
    rules
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_mark_stays_in_top_byte_and_skips_zero_and_fw_mark_prefix() {
        for gen in 0..600u64 {
            let m = policy_mark_for_generation(gen);
            assert_ne!(m, 0);
            assert_eq!(m & CURB_POLICY_MARK_CLEAR, 0);
            assert_ne!(m >> 24, 0x43, "must not collide with CURB_FW_MARK prefix");
            assert_ne!(m >> 24, 0x00);
            assert_ne!(m >> 24, 0xFF);
        }
    }

    #[test]
    fn merge_policy_mark_preserves_lower_24_bit_vpn_marks() {
        let vpn_mark = 0x0008_CA6C;
        let policy = policy_mark_for_generation(4);
        let merged = merge_policy_mark(vpn_mark, policy);
        assert_eq!(merged & CURB_POLICY_MARK_CLEAR, vpn_mark);
        assert_eq!(merged & CURB_POLICY_MARK_MASK, policy);
    }

    #[test]
    fn builds_complete_default_deny_and_dns_redirect_ruleset() {
        let baseline = BaselinePolicy::default();
        let script = build_ruleset(&baseline, 15353, 42, 0x4355_5242);

        assert!(script.contains("table inet curb"));
        assert!(script.contains("delete table inet curb"));
        assert!(script.contains("oifname \"lo\" accept"));
        assert!(script.contains("meta mark 0x43555242 accept"));
        assert!(script.contains("meta mark & 0xff000000 == 0x01000000 ct mark set ct mark & 0x00ffffff | 0x01000000 meta mark set meta mark & 0x00ffffff accept"));
        assert!(script.contains("udp dport { 67, 68, 546, 547 } accept"));
        assert!(script.contains("udp dport 123 accept"));
        assert!(script.contains("th dport 853 reject"));
        assert!(script.contains("th dport 53 reject"));
        assert!(script.contains("ct state invalid drop"));
        assert!(script.contains("ct mark & 0xff000000 == 0x01000000 accept"));
        assert!(!script.contains("ct state established,related ct mark"));
        assert!(script.contains("meta l4proto { tcp, udp } queue num 42"));
        assert!(script.contains("tcp dport 53 redirect to :15353"));
        assert!(script.contains("udp dport 53 redirect to :15353"));
        assert!(!script.contains("meta l4proto { tcp, udp } th dport 53 redirect"));
    }

    #[test]
    fn scopes_dns_redirect_to_ipv4_when_ipv6_proxy_unavailable() {
        let baseline = BaselinePolicy::default();
        let script = build_ruleset_with_options(
            &baseline,
            RulesetOptions {
                dns_proxy_port: 15353,
                redirect_ipv6: false,
                queue_num: 42,
                fw_mark: 0x4355_5242,
                policy_ct_mark: policy_mark_for_generation(7),
            },
        );
        assert!(script.contains("meta nfproto ipv4 tcp dport 53 redirect to :15353"));
        assert!(script.contains("meta nfproto ipv4 udp dport 53 redirect to :15353"));
        assert!(script.contains("ct mark & 0xff000000 == 0x08000000 accept"));
    }

    #[test]
    fn preserves_loopback_dns_proxy_rules_even_when_loopback_baseline_disabled() {
        let baseline = BaselinePolicy {
            dhcp: false,
            loopback: false,
            ntp: false,
            ncsi: false,
        };
        let script = build_ruleset(&baseline, 15353, 42, 0x4355_5242);
        assert!(!script.contains("oifname \"lo\" accept\n"));
        assert!(script.contains("oifname \"lo\" meta l4proto { tcp, udp } th dport 15353 accept"));
        assert!(script.contains("oifname \"lo\" meta l4proto { tcp, udp } th sport 15353 accept"));
        assert!(!script.contains("67, 68"));
        assert!(!script.contains("udp dport 123 accept"));
    }
}
