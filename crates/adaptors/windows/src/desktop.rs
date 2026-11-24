use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use curb_core::adaptors::DesktopIntegration;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HWND};
use windows::Win32::System::Registry::{
    RegCloseKey, RegOpenKeyExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER, KEY_SET_VALUE, REG_DWORD,
    REG_SZ,
};
use windows::Win32::System::Threading::WaitForSingleObject;
use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

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
                let enable_name: Vec<u16> = "ProxyEnable\0".encode_utf16().collect();
                let enable_val: u32 = if enable { 1 } else { 0 };
                let _ = RegSetValueExW(
                    hkey,
                    PCWSTR(enable_name.as_ptr()),
                    0,
                    REG_DWORD,
                    Some(&enable_val.to_le_bytes()),
                );

                if enable {
                    let server_name: Vec<u16> = "ProxyServer\0".encode_utf16().collect();
                    let server_val: Vec<u16> =
                        format!("127.0.0.1:{port}\0").encode_utf16().collect();
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
                }
                let _ = RegCloseKey(hkey);
            }
        }
    }

    fn system_data_dir(&self) -> PathBuf {
        curb_core::store::default_data_dir()
    }

    fn user_data_dir(&self) -> PathBuf {
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            return PathBuf::from(local).join("Curb");
        }
        PathBuf::from(r"C:\ProgramData\Curb")
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
