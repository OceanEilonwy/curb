use std::io::Write;
use std::process::{Command, Stdio};

use curb_core::adaptors::FirewallManager;
use curb_core::config::BaselinePolicy;
use curb_linux::CURB_FW_MARK;

use crate::CURB_NFQUEUE_NUM;

/// Base `ct mark` prefix (`0x4356_0000`, distinct from `CURB_FW_MARK = 0x4355_5242`)
/// used to stamp conntrack entries approved under the current policy generation.
pub const CURB_POLICY_MARK_BASE: u32 = 0x4356_0000;

/// Computes the non-zero `ct mark` value for a 16-bit policy generation counter.
pub fn policy_mark_for_generation(generation: u64) -> u32 {
    let low = ((generation % 0xFFFE) as u32) + 1;
    CURB_POLICY_MARK_BASE | low
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

    let mut rules = String::new();
    rules.push_str("table inet curb\n");
    rules.push_str("delete table inet curb\n");
    rules.push_str("table inet curb {\n");

    rules.push_str("    chain output {\n");
    rules.push_str("        type filter hook output priority 0; policy accept;\n");
    // Packets approved by NFQUEUE are re-injected with `NF_REPEAT` + `NFQA_MARK = policy_ct_mark`.
    // Stamp `ct mark` for the current policy generation and clear `meta mark` so downstream
    // policy-routing / VPN `fwmark` rules are never affected.
    rules.push_str(&format!(
        "        meta mark 0x{policy_ct_mark:08x} ct mark set 0x{policy_ct_mark:08x} meta mark set 0 accept\n"
    ));
    if baseline.loopback {
        rules.push_str("        oifname \"lo\" accept\n");
    }
    rules.push_str(&format!("        meta mark 0x{fw_mark:08x} accept\n"));
    if baseline.dhcp {
        rules.push_str("        udp dport { 67, 68, 546, 547 } accept\n");
    }
    if baseline.ntp {
        rules.push_str("        udp dport 123 accept\n");
    }
    rules.push_str(
        "        icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert, mld-listener-query, mld-listener-report, mld2-listener-report } accept\n",
    );
    // Use `reject` (not `drop`) on DoT port 853 so `systemd-resolved` in opportunistic DoT mode
    // falls back to port 53 (redirected to Curb's DNS proxy) immediately instead of stalling.
    rules.push_str("        meta l4proto { tcp, udp } th dport 853 reject\n");
    rules.push_str("        meta l4proto { tcp, udp } th dport 53 drop\n");
    rules.push_str("        meta l4proto { tcp, udp } ct state invalid drop\n");
    // Fast-path only flows approved under the current policy generation; pre-existing flows
    // or flows from a previous rule/playtime generation fall through to NFQUEUE for re-check.
    rules.push_str(&format!(
        "        ct state established,related ct mark 0x{policy_ct_mark:08x} accept\n"
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
    fn builds_complete_default_deny_and_dns_redirect_ruleset() {
        let baseline = BaselinePolicy::default();
        let script = build_ruleset(&baseline, 15353, 42, 0x4355_5242);

        assert!(script.contains("table inet curb"));
        assert!(script.contains("delete table inet curb"));
        assert!(script.contains("oifname \"lo\" accept"));
        assert!(script.contains("meta mark 0x43555242 accept"));
        assert!(script.contains("udp dport { 67, 68, 546, 547 } accept"));
        assert!(script.contains("udp dport 123 accept"));
        assert!(script.contains("th dport 853 reject"));
        assert!(script.contains("ct state invalid drop"));
        assert!(script.contains("ct state established,related ct mark 0x43560001 accept"));
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
        assert!(script.contains("ct mark 0x43560008 accept"));
    }

    #[test]
    fn omits_disabled_baseline_rules() {
        let baseline = BaselinePolicy {
            dhcp: false,
            loopback: false,
            ntp: false,
            ncsi: false,
        };
        let script = build_ruleset(&baseline, 15353, 42, 0x4355_5242);
        assert!(!script.contains("oifname \"lo\" accept"));
        assert!(!script.contains("67, 68"));
        assert!(!script.contains("udp dport 123 accept"));
    }
}
