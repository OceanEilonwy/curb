use std::path::Path;
use std::process::Command;

use curb_core::store::{dns_backup_path, read_json, write_json_atomic};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// Snapshot of a Windows network adapter's original DNS settings so Curb can
/// cleanly restore DHCP or custom static DNS servers on disable/uninstall.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterDnsBackup {
    pub interface_alias: String,
    pub interface_index: u32,
    pub original_servers: Vec<String>,
}

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

/// Restores every adapter's original DNS configuration from `dns_backup.json`.
pub fn restore_original_adapter_dns(data_dir: &Path) -> Result<(), String> {
    let backup_file = dns_backup_path(data_dir);
    if !backup_file.exists() {
        return Ok(());
    }

    let backups: Vec<AdapterDnsBackup> =
        read_json(&backup_file).map_err(|e| format!("Failed to read DNS backup: {e}"))?;

    for adapter in backups {
        let cmd = if adapter.original_servers.is_empty() {
            format!(
                "Set-DnsClientServerAddress -InterfaceIndex {} -ResetServerAddresses",
                adapter.interface_index
            )
        } else {
            let quoted = adapter
                .original_servers
                .iter()
                .map(|s| format!("'{}'", s.replace('\'', "")))
                .collect::<Vec<_>>()
                .join(",");
            format!(
                "Set-DnsClientServerAddress -InterfaceIndex {} -ServerAddresses ({quoted})",
                adapter.interface_index
            )
        };
        if let Err(e) = run_powershell(&cmd) {
            warn!(
                "Failed to restore DNS for adapter {}: {e}",
                adapter.interface_alias
            );
        }
    }

    let _ = std::fs::remove_file(&backup_file);
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
