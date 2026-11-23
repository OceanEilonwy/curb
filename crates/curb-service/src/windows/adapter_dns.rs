use std::path::Path;
use std::process::Command;

use curb_core::cleanup::{restore_adapter_dns_clean, AdapterDnsBackup};
use curb_core::store::{dns_backup_path, write_json_atomic};
use tracing::info;

/// Snapshots current adapter DNS settings (if not already backed up) and points
/// active Windows network adapters to Curb's local DNS proxy (`127.0.0.1` / `::1`).
pub fn enable_local_dns_redirect(data_dir: &Path) -> Result<(), String> {
    let backup_file = dns_backup_path(data_dir);
    if !backup_file.exists() {
        let snapshot = capture_adapter_dns_snapshot()?;
        write_json_atomic(&backup_file, &snapshot).map_err(|e| e.to_string())?;
        info!("Backed up DNS settings for {} adapters", snapshot.len());
    }

    // Point active adapters to 127.0.0.1 (IPv4) and ::1 (IPv6)
    let ps = r#"
        Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object {
            Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ServerAddresses ('127.0.0.1','::1')
        }
    "#;
    run_powershell(ps)?;
    info!("Pointed active network adapters to Curb local DNS proxy (127.0.0.1 / ::1)");
    Ok(())
}

/// Restores every adapter's original DNS configuration from `dns_backup.json`
/// and resets any adapter still pointed at `127.0.0.1` / `::1` back to DHCP.
pub fn restore_original_adapter_dns(data_dir: &Path) -> Result<(), String> {
    restore_adapter_dns_clean(data_dir)?;
    info!("Restored original network adapter DNS settings");
    Ok(())
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
