use std::path::Path;

use serde::{Deserialize, Serialize};

/// Stable Curb WFP Provider GUID (u128 representation so it's usable cross-platform).
pub const CURB_PROVIDER_UUID: u128 = 0x7c8e94b1_4412_4f68_a13b_2210c8894e01;

/// Stable Curb WFP Sublayer GUID.
pub const CURB_SUBLAYER_UUID: u128 = 0x7c8e94b1_4412_4f68_a13b_2210c8894e02;

/// Snapshot of a Windows network adapter's original DNS settings saved in
/// `C:\ProgramData\Curb\dns_backup.json` before Curb redirects DNS to `127.0.0.1`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterDnsBackup {
    pub interface_alias: String,
    pub interface_index: u32,
    pub original_servers: Vec<String>,
    #[serde(default)]
    pub v4_static: bool,
    #[serde(default)]
    pub v6_static: bool,
}

/// Removes ALL WFP filters owned by Curb (including persistent default-deny filters),
/// plus Curb's WFP sublayer and provider. Safe to call even if CurbService is stopped
/// or previously crashed.
pub fn purge_all_curb_wfp_objects() -> Result<usize, String> {
    #[cfg(windows)]
    {
        windows_impl::purge_wfp()
    }

    #[cfg(not(windows))]
    {
        Ok(0)
    }
}

/// Restores every adapter's original DNS settings from `dns_backup.json`, AND as a
/// fail-safe resets any active adapter still pointed at `127.0.0.1` or `::1` back to
/// automatic DHCP DNS so uninstalling/disabling can never strand a PC offline.
pub fn restore_adapter_dns_clean(data_dir: &Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        windows_impl::restore_dns(data_dir)
    }

    #[cfg(not(windows))]
    {
        let _ = data_dir;
        Ok(())
    }
}

#[cfg(windows)]
mod windows_impl {
    use std::path::Path;
    use std::process::Command;
    use std::ptr;

    use windows::core::GUID;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
        FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterCreateEnumHandle0, FwpmFilterDeleteById0,
        FwpmFilterDestroyEnumHandle0, FwpmFilterEnum0, FwpmFreeMemory0,
        FwpmProviderDeleteByKey0, FwpmSubLayerDeleteByKey0, FWPM_FILTER0,
        FWPM_FILTER_ENUM_TEMPLATE0,
    };
    use windows::Win32::System::Rpc::RPC_C_AUTHN_DEFAULT;

    use crate::store::{dns_backup_path, read_json};

    use super::{AdapterDnsBackup, CURB_PROVIDER_UUID, CURB_SUBLAYER_UUID};

    pub fn purge_wfp() -> Result<usize, String> {
        let mut engine = HANDLE::default();
        let code = unsafe {
            FwpmEngineOpen0(
                None,
                RPC_C_AUTHN_DEFAULT as u32,
                None,
                None,
                &mut engine,
            )
        };
        if code != 0 {
            return Err(format!("FwpmEngineOpen0 failed: 0x{code:08x}"));
        }

        let provider_guid = GUID::from_u128(CURB_PROVIDER_UUID);
        let sublayer_guid = GUID::from_u128(CURB_SUBLAYER_UUID);

        let template = FWPM_FILTER_ENUM_TEMPLATE0 {
            providerKey: &provider_guid as *const _ as *mut _,
            ..Default::default()
        };

        let mut enum_handle = HANDLE::default();
        let mut deleted = 0usize;

        let create_code = unsafe {
            FwpmFilterCreateEnumHandle0(engine, Some(&template), &mut enum_handle)
        };

        if create_code == 0 {
            loop {
                let mut entries: *mut *mut FWPM_FILTER0 = ptr::null_mut();
                let mut returned = 0u32;
                let enum_code = unsafe {
                    FwpmFilterEnum0(engine, enum_handle, 256, &mut entries, &mut returned)
                };
                if enum_code != 0 || returned == 0 || entries.is_null() {
                    break;
                }

                let slice = unsafe { std::slice::from_raw_parts(entries, returned as usize) };
                for &filter_ptr in slice {
                    if !filter_ptr.is_null() {
                        let filter_id = unsafe { (*filter_ptr).filterId };
                        if unsafe { FwpmFilterDeleteById0(engine, filter_id) } == 0 {
                            deleted += 1;
                        }
                    }
                }

                unsafe {
                    let mut raw = entries as *mut std::ffi::c_void;
                    FwpmFreeMemory0(&mut raw);
                }

                if returned < 256 {
                    break;
                }
            }

            unsafe {
                let _ = FwpmFilterDestroyEnumHandle0(engine, enum_handle);
            }
        }

        unsafe {
            let _ = FwpmSubLayerDeleteByKey0(engine, &sublayer_guid);
            let _ = FwpmProviderDeleteByKey0(engine, &provider_guid);
            let _ = FwpmEngineClose0(engine);
        }

        Ok(deleted)
    }

    pub fn restore_dns(data_dir: &Path) -> Result<(), String> {
        let backup_file = dns_backup_path(data_dir);
        if backup_file.exists() {
            if let Ok(backups) = read_json::<Vec<AdapterDnsBackup>>(&backup_file) {
                for adapter in backups {
                    // Always reset the interface back to DHCP first to clear both IPv4 (127.0.0.1)
                    // and IPv6 (::1) overrides before selectively restoring any static DNS family.
                    let reset_cmd = format!(
                        "Set-DnsClientServerAddress -InterfaceIndex {} -ResetServerAddresses -ErrorAction SilentlyContinue",
                        adapter.interface_index
                    );
                    let _ = run_powershell(&reset_cmd);

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
                            let cmd = format!(
                                "Set-DnsClientServerAddress -InterfaceIndex {} -ServerAddresses ({}) -ErrorAction SilentlyContinue",
                                adapter.interface_index,
                                v4_servers.join(",")
                            );
                            let _ = run_powershell(&cmd);
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
                            let cmd = format!(
                                "Set-DnsClientServerAddress -InterfaceIndex {} -ServerAddresses ({}) -ErrorAction SilentlyContinue",
                                adapter.interface_index,
                                v6_servers.join(",")
                            );
                            let _ = run_powershell(&cmd);
                        }
                    }
                }
            }
            let _ = std::fs::remove_file(&backup_file);
        }

        // Fail-safe sweep: reset any adapter still pointed at Curb's 127.0.0.1 / ::1 back to DHCP
        // and flush Windows DNS client cache.
        let sweep = r#"
            Get-NetAdapter | ForEach-Object {
                $idx = $_.ifIndex
                $addrs = @(Get-DnsClientServerAddress -InterfaceIndex $idx -ErrorAction SilentlyContinue | ForEach-Object { $_.ServerAddresses })
                if ($addrs -contains '127.0.0.1' -or $addrs -contains '::1') {
                    Set-DnsClientServerAddress -InterfaceIndex $idx -ResetServerAddresses -ErrorAction SilentlyContinue
                }
            }
            Clear-DnsClientCache -ErrorAction SilentlyContinue
        "#;
        let _ = run_powershell(sweep);
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
}
