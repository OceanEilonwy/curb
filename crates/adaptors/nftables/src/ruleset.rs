use std::io::Write;
use std::process::{Command, Stdio};

use curb_core::adaptors::FirewallManager;
use curb_core::config::BaselinePolicy;
use curb_linux::CURB_FW_MARK;

use crate::CURB_NFQUEUE_NUM;

/// Linux `nftables` + `NFQUEUE` implementation of [`FirewallManager`].
#[derive(Debug, Default, Clone, Copy)]
pub struct NftablesFirewall;

impl FirewallManager for NftablesFirewall {
    fn apply_enforcing(
        &self,
        baseline: &BaselinePolicy,
        dns_proxy_port: u16,
    ) -> Result<(), String> {
        let script = build_ruleset(baseline, dns_proxy_port, CURB_NFQUEUE_NUM, CURB_FW_MARK);
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
    let mut rules = String::new();
    rules.push_str("table inet curb\n");
    rules.push_str("delete table inet curb\n");
    rules.push_str("table inet curb {\n");

    rules.push_str("    chain output {\n");
    rules.push_str("        type filter hook output priority 0; policy accept;\n");
    if baseline.loopback {
        rules.push_str("        oifname \"lo\" accept\n");
    }
    rules.push_str("        ct state established,related accept\n");
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
    rules.push_str("        meta l4proto { tcp, udp } th dport 853 drop\n");
    rules.push_str("        meta l4proto { tcp, udp } th dport 53 drop\n");
    rules.push_str(&format!(
        "        ct state new meta l4proto {{ tcp, udp }} queue num {queue_num}\n"
    ));
    rules.push_str("    }\n");

    rules.push_str("    chain nat_output {\n");
    rules.push_str("        type nat hook output priority -100; policy accept;\n");
    rules.push_str(&format!("        meta mark 0x{fw_mark:08x} return\n"));
    rules.push_str(&format!(
        "        meta l4proto {{ tcp, udp }} th dport 53 redirect to :{dns_proxy_port}\n"
    ));
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
        let script = build_ruleset(&baseline, 5353, 42, 0x4355_5242);

        assert!(script.contains("table inet curb"));
        assert!(script.contains("delete table inet curb"));
        assert!(script.contains("oifname \"lo\" accept"));
        assert!(script.contains("meta mark 0x43555242 accept"));
        assert!(script.contains("udp dport { 67, 68, 546, 547 } accept"));
        assert!(script.contains("udp dport 123 accept"));
        assert!(script.contains("th dport 853 drop"));
        assert!(script.contains("ct state new meta l4proto { tcp, udp } queue num 42"));
        assert!(script.contains("th dport 53 redirect to :5353"));
    }

    #[test]
    fn omits_disabled_baseline_rules() {
        let baseline = BaselinePolicy {
            dhcp: false,
            loopback: false,
            ntp: false,
            ncsi: false,
        };
        let script = build_ruleset(&baseline, 5353, 42, 0x4355_5242);
        assert!(!script.contains("oifname \"lo\" accept"));
        assert!(!script.contains("67, 68"));
        assert!(!script.contains("udp dport 123 accept"));
    }
}
