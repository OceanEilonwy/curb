use std::net::SocketAddr;
use std::path::Path;
use std::process::Command;

use curb_core::adaptors::DnsManager;
use curb_core::cleanup::AdapterDnsBackup;
use curb_core::store::{dns_backup_path, read_json};

/// Windows Adapter DNS cleanup adaptor.
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsDnsManager;

impl DnsManager for WindowsDnsManager {
    fn discover_upstreams(&self) -> Vec<SocketAddr> {
        Vec::new()
    }

    fn restore_clean(&self, data_dir: &Path) -> Result<(), String> {
        restore_adapter_dns_clean(data_dir)
    }
}

/// Restores every adapter's original DNS settings from `dns_backup.json`, AND as a
/// fail-safe resets any active adapter still pointed at `127.0.0.1` or `::1` back to
/// automatic DHCP DNS.
pub fn restore_adapter_dns_clean(data_dir: &Path) -> Result<(), String> {
    let mut script = String::new();
    let backup_file = dns_backup_path(data_dir);
    if backup_file.exists() {
        if let Ok(backups) = read_json::<Vec<AdapterDnsBackup>>(&backup_file) {
            for adapter in backups {
                script.push_str(&format!(
                    "Set-DnsClientServerAddress -InterfaceIndex {} -ResetServerAddresses -ErrorAction SilentlyContinue\n",
                    adapter.interface_index
                ));

                if adapter.v4_static {
                    let v4_servers: Vec<String> = adapter
                        .original_servers
                        .iter()
                        .filter(|s| {
                            s.trim()
                                .parse::<std::net::Ipv4Addr>()
                                .is_ok_and(|ip| !ip.is_loopback() && !ip.is_unspecified())
                        })
                        .map(|s| format!("'{}'", s.replace('\'', "")))
                        .collect();
                    if !v4_servers.is_empty() {
                        script.push_str(&format!(
                            "Set-DnsClientServerAddress -InterfaceIndex {} -ServerAddresses ({}) -ErrorAction SilentlyContinue\n",
                            adapter.interface_index,
                            v4_servers.join(",")
                        ));
                    }
                }

                if adapter.v6_static {
                    let v6_servers: Vec<String> = adapter
                        .original_servers
                        .iter()
                        .filter(|s| {
                            s.trim().parse::<std::net::Ipv6Addr>().is_ok_and(|ip| {
                                let prefix = ip.segments()[0] & 0xffc0;
                                !ip.is_loopback()
                                    && !ip.is_unspecified()
                                    && prefix != 0xfe80
                                    && prefix != 0xfec0
                            })
                        })
                        .map(|s| format!("'{}'", s.replace('\'', "")))
                        .collect();
                    if !v6_servers.is_empty() {
                        script.push_str(&format!(
                            "Set-DnsClientServerAddress -InterfaceIndex {} -ServerAddresses ({}) -ErrorAction SilentlyContinue\n",
                            adapter.interface_index,
                            v6_servers.join(",")
                        ));
                    }
                }
            }
        }
    }

    script.push_str(
        r#"
Get-DnsClientServerAddress -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses -contains '127.0.0.1' -or $_.ServerAddresses -contains '::1' } | Select-Object -ExpandProperty InterfaceIndex -Unique | ForEach-Object {
    Set-DnsClientServerAddress -InterfaceIndex $_ -ResetServerAddresses -ErrorAction SilentlyContinue
}
Clear-DnsClientCache -ErrorAction SilentlyContinue
"#,
    );
    run_powershell(&script)?;
    if backup_file.exists() {
        let _ = std::fs::remove_file(&backup_file);
    }
    Ok(())
}

fn run_powershell(script: &str) -> Result<String, String> {
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .map_err(|e| format!("Failed to invoke PowerShell: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(stderr.trim().to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}
