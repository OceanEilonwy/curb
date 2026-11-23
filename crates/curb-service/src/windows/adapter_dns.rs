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

    // Only modify active adapters that are not already pointed at Curb's local DNS
    // so repeated baseline updates do not needlessly bounce Wi-Fi adapters.
    let ps = if include_ipv6 {
        r#"
            Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object {
                $idx = $_.ifIndex
                $cur = @(Get-DnsClientServerAddress -InterfaceIndex $idx -ErrorAction SilentlyContinue | ForEach-Object { $_.ServerAddresses })
                $already = ($cur.Count -gt 0) -and ($cur -contains '127.0.0.1') -and (($cur | Where-Object { $_ -ne '127.0.0.1' -and $_ -ne '::1' }).Count -eq 0)
                if (-not $already) {
                    Set-DnsClientServerAddress -InterfaceIndex $idx -ServerAddresses ('127.0.0.1','::1') -ErrorAction SilentlyContinue
                    if (-not $?) {
                        Set-DnsClientServerAddress -InterfaceIndex $idx -ServerAddresses ('127.0.0.1') -ErrorAction SilentlyContinue
                    }
                }
            }
        "#
    } else {
        r#"
            Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object {
                $idx = $_.ifIndex
                $cur = @(Get-DnsClientServerAddress -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { $_.ServerAddresses })
                $already = ($cur.Count -eq 1) -and ($cur[0] -eq '127.0.0.1')
                if (-not $already) {
                    Set-DnsClientServerAddress -InterfaceIndex $idx -ServerAddresses ('127.0.0.1') -ErrorAction SilentlyContinue
                }
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
    let mut out = Vec::new();
    for adapter in backups {
        for raw in &adapter.original_servers {
            let trimmed = raw.trim();
            let Ok(ip) = trimmed.parse::<IpAddr>() else {
                continue;
            };
            if ip.is_loopback() || ip.is_unspecified() {
                continue;
            }
            // Skip IPv6 link-local addresses (fe80::/10) which require an interface scope ID.
            if let IpAddr::V6(v6) = ip {
                if (v6.segments()[0] & 0xffc0) == 0xfe80 {
                    continue;
                }
            }
            let addr = SocketAddr::new(ip, 53);
            if !out.contains(&addr) {
                out.push(addr);
            }
        }
    }
    out
}

fn capture_adapter_dns_snapshot() -> Result<Vec<AdapterDnsBackup>, String> {
    let ps = r#"
        $items = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object {
            $dns = Get-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                interface_alias = $_.Name
                interface_index = [int]$_.ifIndex
                original_servers = @($dns | ForEach-Object { $_.ServerAddresses } | Where-Object { $_ -and $_ -ne '127.0.0.1' -and $_ -ne '::1' })
            }
        }
        ConvertTo-Json -InputObject @($items) -Compress
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
