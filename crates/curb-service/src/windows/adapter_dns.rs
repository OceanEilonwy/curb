use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::process::Command;

use curb_core::cleanup::{restore_adapter_dns_clean, AdapterDnsBackup};
use curb_core::store::{dns_backup_path, read_json, write_json_atomic};
use tracing::info;

/// Snapshots current adapter DNS settings (if not already backed up), points
/// active Windows network adapters to Curb's local DNS proxy (`127.0.0.1`, plus
/// `::1` when Curb's IPv6 DNS listener is bound), and returns the original
/// non-loopback upstream DNS servers so Curb's DNS proxy can forward to the
/// network's real resolvers first.
pub fn enable_local_dns_redirect(
    data_dir: &Path,
    include_ipv6: bool,
) -> Result<Vec<SocketAddr>, String> {
    let backup_file = dns_backup_path(data_dir);
    let backups = if !backup_file.exists() {
        let snapshot = capture_adapter_dns_snapshot()?;
        write_json_atomic(&backup_file, &snapshot).map_err(|e| e.to_string())?;
        info!("Backed up DNS settings for {} adapters", snapshot.len());
        snapshot
    } else {
        read_json::<Vec<AdapterDnsBackup>>(&backup_file).unwrap_or_default()
    };

    let upstreams = extract_upstream_servers(&backups);

    // Set IPv4 and IPv6 DNS in separate calls because MSFT_DNSClientServerAddress
    // has distinct per-family CIM instances and rejects mixed IPv4+IPv6 arrays.
    let ps = if include_ipv6 {
        r#"
            $changed = $false
            Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object {
                $idx = $_.ifIndex
                $v4 = @(Get-DnsClientServerAddress -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { $_.ServerAddresses })
                if (-not (($v4.Count -eq 1) -and ($v4[0] -eq '127.0.0.1'))) {
                    Set-DnsClientServerAddress -InterfaceIndex $idx -ServerAddresses ('127.0.0.1') -ErrorAction SilentlyContinue
                    $changed = $true
                }
                $v6 = @(Get-DnsClientServerAddress -InterfaceIndex $idx -AddressFamily IPv6 -ErrorAction SilentlyContinue | ForEach-Object { $_.ServerAddresses })
                if (-not (($v6.Count -eq 1) -and ($v6[0] -eq '::1'))) {
                    Set-DnsClientServerAddress -InterfaceIndex $idx -ServerAddresses ('::1') -ErrorAction SilentlyContinue
                    $changed = $true
                }
            }
            if ($changed) {
                Clear-DnsClientCache -ErrorAction SilentlyContinue
            }
        "#
    } else {
        r#"
            $changed = $false
            Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object {
                $idx = $_.ifIndex
                $v4 = @(Get-DnsClientServerAddress -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { $_.ServerAddresses })
                if (-not (($v4.Count -eq 1) -and ($v4[0] -eq '127.0.0.1'))) {
                    Set-DnsClientServerAddress -InterfaceIndex $idx -ServerAddresses ('127.0.0.1') -ErrorAction SilentlyContinue
                    $changed = $true
                }
            }
            if ($changed) {
                Clear-DnsClientCache -ErrorAction SilentlyContinue
            }
        "#
    };

    run_powershell(ps)?;
    info!(
        "Pointed active network adapters to Curb local DNS proxy (127.0.0.1{}; {} original upstreams captured)",
        if include_ipv6 { " / ::1" } else { "" },
        upstreams.len()
    );
    Ok(upstreams)
}

/// Restores every adapter's original DNS configuration from `dns_backup.json`
/// and resets any adapter still pointed at `127.0.0.1` / `::1` back to DHCP.
pub fn restore_original_adapter_dns(data_dir: &Path) -> Result<(), String> {
    restore_adapter_dns_clean(data_dir)?;
    info!("Restored original network adapter DNS settings");
    Ok(())
}

fn extract_upstream_servers(backups: &[AdapterDnsBackup]) -> Vec<SocketAddr> {
    let mut v4_out = Vec::new();
    let mut v6_out = Vec::new();
    for adapter in backups {
        for raw in &adapter.original_servers {
            let trimmed = raw.trim();
            let Ok(ip) = trimmed.parse::<IpAddr>() else {
                continue;
            };
            if ip.is_loopback() || ip.is_unspecified() {
                continue;
            }
            match ip {
                IpAddr::V4(_) => {
                    let addr = SocketAddr::new(ip, 53);
                    if !v4_out.contains(&addr) {
                        v4_out.push(addr);
                    }
                }
                IpAddr::V6(v6) => {
                    // Skip IPv6 link-local (fe80::/10) and Windows site-local placeholder
                    // addresses (fec0::/10, e.g. fec0:0:0:ffff::1..3) which are not routable.
                    let prefix = v6.segments()[0] & 0xffc0;
                    if prefix == 0xfe80 || prefix == 0xfec0 {
                        continue;
                    }
                    let addr = SocketAddr::new(ip, 53);
                    if !v6_out.contains(&addr) {
                        v6_out.push(addr);
                    }
                }
            }
        }
    }
    v4_out.extend(v6_out);
    v4_out
}

fn capture_adapter_dns_snapshot() -> Result<Vec<AdapterDnsBackup>, String> {
    let ps = r#"
        $items = @(Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object {
            $dns = Get-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                interface_alias = $_.Name
                interface_index = [int]$_.ifIndex
                original_servers = @($dns | ForEach-Object { $_.ServerAddresses } | Where-Object {
                    $_ -and $_ -ne '127.0.0.1' -and $_ -ne '::1' -and $_ -notlike 'fec0:*' -and $_ -notlike 'fe80:*'
                })
            }
        })
        ConvertTo-Json -InputObject $items -Depth 4 -Compress
    "#;
    let out = run_powershell(ps)?;
    if out.trim().is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str(&out).map_err(|e| format!("Failed to parse adapter DNS snapshot: {e}"))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_out_fec0_fe80_and_loopback_and_prioritizes_ipv4_upstreams() {
        let backups = vec![AdapterDnsBackup {
            interface_alias: "Wi-Fi".into(),
            interface_index: 12,
            original_servers: vec![
                "127.0.0.1".into(),
                "::1".into(),
                "fec0:0:0:ffff::1".into(),
                "fec0:0:0:ffff::2".into(),
                "fec0:0:0:ffff::3".into(),
                "fe80::1".into(),
                "2606:4700:4700::1111".into(),
                "192.168.1.1".into(),
            ],
        }];

        let upstreams = extract_upstream_servers(&backups);
        assert_eq!(
            upstreams,
            vec![
                "192.168.1.1:53".parse::<SocketAddr>().unwrap(),
                "[2606:4700:4700::1111]:53".parse::<SocketAddr>().unwrap(),
            ]
        );
    }
}
