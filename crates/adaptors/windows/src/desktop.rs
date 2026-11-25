use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use curb_core::adaptors::{AppIcon, AppIconRequest, DesktopIntegration};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HWND};
use windows::Win32::Networking::WinInet::{
    InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
};
use windows::Win32::System::Registry::{
    RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY,
    HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_DWORD, REG_SZ, REG_VALUE_TYPE,
};
use windows::Win32::System::Threading::WaitForSingleObject;
use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

const CURB_STANDARD_PROXY_ADDR: &str = "127.0.0.1:48921";

/// Cleans up Curb's per-user Windows desktop state (`HKCU\...\Run\Curb`,
/// `HKCU\...\Internet Settings` Standard Mode proxy if pointing at Curb,
/// `%LOCALAPPDATA%\Curb\standard_mode.flag`, and optionally `config.json`/`auth.json`).
pub fn cleanup_user_desktop_config(remove_user_data: bool) -> Vec<String> {
    let mut cleaned = Vec::new();

    // 1. Remove HKCU tray auto-start entry
    let run_subkey: Vec<u16> = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\0"
        .encode_utf16()
        .collect();
    let run_value: Vec<u16> = "Curb\0".encode_utf16().collect();
    unsafe {
        let mut hkey = HKEY::default();
        if RegOpenKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(run_subkey.as_ptr()),
            0,
            KEY_SET_VALUE,
            &mut hkey,
        )
        .is_ok()
        {
            if RegDeleteValueW(hkey, PCWSTR(run_value.as_ptr())).is_ok() {
                cleaned.push("Removed HKCU\\...\\Run\\Curb autostart entry".into());
            }
            let _ = RegCloseKey(hkey);
        }
    }

    // 2. Reset HKCU Internet Settings proxy ONLY if it points to Curb's Standard Mode proxy
    let inet_subkey: Vec<u16> =
        "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\0"
            .encode_utf16()
            .collect();
    let proxy_server_name: Vec<u16> = "ProxyServer\0".encode_utf16().collect();
    let proxy_enable_name: Vec<u16> = "ProxyEnable\0".encode_utf16().collect();
    unsafe {
        let mut hkey = HKEY::default();
        if RegOpenKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(inet_subkey.as_ptr()),
            0,
            KEY_QUERY_VALUE | KEY_SET_VALUE,
            &mut hkey,
        )
        .is_ok()
        {
            let mut val_type = REG_VALUE_TYPE::default();
            let mut buf = [0u16; 256];
            let mut byte_len = (buf.len() * 2) as u32;
            let matches_curb_proxy = RegQueryValueExW(
                hkey,
                PCWSTR(proxy_server_name.as_ptr()),
                None,
                Some(&mut val_type),
                Some(buf.as_mut_ptr() as *mut u8),
                Some(&mut byte_len),
            )
            .is_ok()
                && val_type == REG_SZ
                && {
                    let u16_len = (byte_len as usize) / 2;
                    let slice = &buf[..u16_len.min(buf.len())];
                    let trimmed = slice.iter().take_while(|&&c| c != 0).copied().collect::<Vec<_>>();
                    String::from_utf16_lossy(&trimmed) == CURB_STANDARD_PROXY_ADDR
                };

            if matches_curb_proxy {
                let disable_val: u32 = 0;
                let _ = RegSetValueExW(
                    hkey,
                    PCWSTR(proxy_enable_name.as_ptr()),
                    0,
                    REG_DWORD,
                    Some(&disable_val.to_le_bytes()),
                );
                let _ = RegDeleteValueW(hkey, PCWSTR(proxy_server_name.as_ptr()));
                cleaned.push("Reset HKCU Standard Mode proxy settings".into());
                let _ = RegCloseKey(hkey);
                notify_wininet_proxy_changed();
            } else {
                let _ = RegCloseKey(hkey);
            }
        }
    }

    // 3. Remove Standard Mode marker (and user config/auth on --purge)
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        let user_dir = PathBuf::from(local).join("Curb");
        let flag = user_dir.join("standard_mode.flag");
        if flag.exists() && std::fs::remove_file(&flag).is_ok() {
            cleaned.push(format!("Removed {}", flag.display()));
        }
        if remove_user_data {
            for name in ["config.json", "auth.json"] {
                let p = user_dir.join(name);
                if p.exists() && std::fs::remove_file(&p).is_ok() {
                    cleaned.push(format!("Removed {}", p.display()));
                }
            }
        }
    }

    cleaned
}

/// Windows UAC (`runas`), Registry (`HKCU\Run`, Internet Settings proxy), and data-path adaptor.
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsDesktopIntegration;

impl DesktopIntegration for WindowsDesktopIntegration {
    fn launch_elevated_install(&self, migrate_from: &Path) -> Result<(), String> {
        let (cli_path, svc_path) = locate_bundled_binaries()?;
        let params = format!(
            "install --service-bin \"{}\" --migrate-from \"{}\"",
            svc_path.display(),
            migrate_from.display()
        );
        run_elevated_windows(&cli_path, &params)
    }

    fn launch_elevated_uninstall(&self) -> Result<(), String> {
        let (cli_path, _) = locate_bundled_binaries()?;
        run_elevated_windows(&cli_path, "uninstall")
    }

    fn ensure_tray_autostart(&self) {
        let Ok(exe) = std::env::current_exe() else {
            return;
        };
        let subkey: Vec<u16> = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\0"
            .encode_utf16()
            .collect();
        let value_name: Vec<u16> = "Curb\0".encode_utf16().collect();
        let quoted_exe: Vec<u16> = format!("\"{}\"\0", exe.display()).encode_utf16().collect();

        unsafe {
            let mut hkey = HKEY::default();
            if RegOpenKeyExW(
                HKEY_CURRENT_USER,
                PCWSTR(subkey.as_ptr()),
                0,
                KEY_SET_VALUE,
                &mut hkey,
            )
            .is_ok()
            {
                let bytes = std::slice::from_raw_parts(
                    quoted_exe.as_ptr() as *const u8,
                    quoted_exe.len() * 2,
                );
                let _ = RegSetValueExW(
                    hkey,
                    PCWSTR(value_name.as_ptr()),
                    0,
                    REG_SZ,
                    Some(bytes),
                );
                let _ = RegCloseKey(hkey);
            }
        }
    }

    fn set_user_proxy(&self, enable: bool, port: u16) {
        let subkey: Vec<u16> = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\0"
            .encode_utf16()
            .collect();
        let expected_server = format!("127.0.0.1:{port}");
        let mut updated = false;
        unsafe {
            let mut hkey = HKEY::default();
            if RegOpenKeyExW(
                HKEY_CURRENT_USER,
                PCWSTR(subkey.as_ptr()),
                0,
                KEY_QUERY_VALUE | KEY_SET_VALUE,
                &mut hkey,
            )
            .is_ok()
            {
                let enable_name: Vec<u16> = "ProxyEnable\0".encode_utf16().collect();
                let server_name: Vec<u16> = "ProxyServer\0".encode_utf16().collect();
                let enable_val: u32 = if enable { 1 } else { 0 };
                let _ = RegSetValueExW(
                    hkey,
                    PCWSTR(enable_name.as_ptr()),
                    0,
                    REG_DWORD,
                    Some(&enable_val.to_le_bytes()),
                );

                if enable {
                    let server_val: Vec<u16> =
                        format!("{expected_server}\0").encode_utf16().collect();
                    let bytes = std::slice::from_raw_parts(
                        server_val.as_ptr() as *const u8,
                        server_val.len() * 2,
                    );
                    let _ = RegSetValueExW(
                        hkey,
                        PCWSTR(server_name.as_ptr()),
                        0,
                        REG_SZ,
                        Some(bytes),
                    );

                    let override_name: Vec<u16> = "ProxyOverride\0".encode_utf16().collect();
                    let override_val: Vec<u16> =
                        "localhost;127.0.0.1;<local>\0".encode_utf16().collect();
                    let obytes = std::slice::from_raw_parts(
                        override_val.as_ptr() as *const u8,
                        override_val.len() * 2,
                    );
                    let _ = RegSetValueExW(
                        hkey,
                        PCWSTR(override_name.as_ptr()),
                        0,
                        REG_SZ,
                        Some(obytes),
                    );
                } else {
                    let mut val_type = REG_VALUE_TYPE::default();
                    let mut buf = [0u16; 256];
                    let mut byte_len = (buf.len() * 2) as u32;
                    let matches_curb_proxy = RegQueryValueExW(
                        hkey,
                        PCWSTR(server_name.as_ptr()),
                        None,
                        Some(&mut val_type),
                        Some(buf.as_mut_ptr() as *mut u8),
                        Some(&mut byte_len),
                    )
                    .is_ok()
                        && val_type == REG_SZ
                        && {
                            let u16_len = (byte_len as usize) / 2;
                            let slice = &buf[..u16_len.min(buf.len())];
                            let trimmed = slice
                                .iter()
                                .take_while(|&&c| c != 0)
                                .copied()
                                .collect::<Vec<_>>();
                            String::from_utf16_lossy(&trimmed) == expected_server
                        };
                    if matches_curb_proxy {
                        let _ = RegDeleteValueW(hkey, PCWSTR(server_name.as_ptr()));
                    }
                }
                let _ = RegCloseKey(hkey);
                updated = true;
            }
        }
        if updated {
            notify_wininet_proxy_changed();
        }
    }

    fn system_data_dir(&self) -> PathBuf {
        crate::default_data_dir()
    }

    fn user_data_dir(&self) -> PathBuf {
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            return PathBuf::from(local).join("Curb");
        }
        crate::default_data_dir()
    }

    fn exe_path_prompt(&self) -> (&'static str, &'static str) {
        (
            "Enter or paste the full path to an executable (.exe) on this computer.",
            r"C:\Program Files\Example\App.exe",
        )
    }

    fn resolve_app_icon(&self, req: &AppIconRequest<'_>) -> Option<AppIcon> {
        crate::icons::resolve_app_icon(req)
    }
}

fn locate_bundled_binaries() -> Result<(PathBuf, PathBuf), String> {
    let mut search_dirs = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            search_dirs.push(dir.join("resources"));
            search_dirs.push(dir.to_path_buf());
        }
    }

    for dir in search_dirs {
        let cli = dir.join("curb-cli.exe");
        let svc = dir.join("curb-service.exe");
        if cli.exists() && svc.exists() {
            return Ok((cli, svc));
        }
    }

    Err(
        "Could not find bundled curb-cli.exe and curb-service.exe next to Curb. Re-download the full Windows installer."
            .into(),
    )
}

fn run_elevated_windows(exe: &Path, params: &str) -> Result<(), String> {
    let verb: Vec<u16> = "runas\0".encode_utf16().collect();
    let file: Vec<u16> = OsStr::new(exe)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let args: Vec<u16> = params.encode_utf16().chain(std::iter::once(0)).collect();

    let mut sei = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        hwnd: HWND::default(),
        lpVerb: PCWSTR(verb.as_ptr()),
        lpFile: PCWSTR(file.as_ptr()),
        lpParameters: PCWSTR(args.as_ptr()),
        lpDirectory: PCWSTR::null(),
        nShow: SW_HIDE.0,
        ..Default::default()
    };

    unsafe {
        ShellExecuteExW(&mut sei)
            .map_err(|_| "Administrator approval was canceled or blocked.".to_string())?;
        if !sei.hProcess.is_invalid() && !sei.hProcess.0.is_null() {
            let _ = WaitForSingleObject(sei.hProcess, 30_000);
            let _ = CloseHandle(sei.hProcess);
        }
    }
    Ok(())
}

/// Broadcasts `INTERNET_OPTION_SETTINGS_CHANGED` + `INTERNET_OPTION_REFRESH` to WinINet so
/// browsers and Electron/Chromium apps (e.g. Discord, Edge, Chrome) immediately pick up
/// `HKCU\...\Internet Settings` proxy changes without keeping stale proxy routes.
fn notify_wininet_proxy_changed() {
    unsafe {
        let _ = InternetSetOptionW(None, INTERNET_OPTION_SETTINGS_CHANGED, None, 0);
        let _ = InternetSetOptionW(None, INTERNET_OPTION_REFRESH, None, 0);
    }
}

