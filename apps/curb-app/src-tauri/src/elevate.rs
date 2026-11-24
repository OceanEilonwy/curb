use std::path::PathBuf;
use tauri::{AppHandle, Manager};

use crate::local_mode::user_data_dir;

/// Locates bundled `curb-cli.exe` and `curb-service.exe` inside the Tauri resource
/// directory (or sibling executable directory) and triggers a single Windows UAC
/// elevation prompt (`runas`) to install & start `CurbService` in `C:\ProgramData\Curb`.
pub fn launch_elevated_service_install(app: &AppHandle) -> Result<(), String> {
    #[cfg(windows)]
    {
        let (cli_path, svc_path) = locate_bundled_binaries(app)?;
        let migrate_dir = user_data_dir();
        let params = format!(
            "install --service-bin \"{}\" --migrate-from \"{}\"",
            svc_path.display(),
            migrate_dir.display()
        );

        run_elevated_windows(&cli_path, &params)
    }

    #[cfg(not(windows))]
    {
        let _ = app;
        Err("Full Protection (Windows Service + WFP) is only available on Windows.".into())
    }
}

/// Returns true if a running `CurbService` reports a different version than this
/// `curb-app` build (e.g. after running a per-user NSIS update while an older
/// `C:\ProgramData\Curb\bin\curb-service.exe` was already running).
pub fn is_service_outdated(reported_version: &str) -> bool {
    reported_version != env!("CARGO_PKG_VERSION")
}

#[cfg(windows)]
fn locate_bundled_binaries(app: &AppHandle) -> Result<(PathBuf, PathBuf), String> {
    let mut search_dirs = Vec::new();
    if let Ok(res_dir) = app.path().resource_dir() {
        search_dirs.push(res_dir.join("resources"));
        search_dirs.push(res_dir);
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
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

/// Triggers a single Windows UAC prompt (`runas`) to stop and unregister `CurbService`.
pub fn launch_elevated_service_uninstall(app: &AppHandle) -> Result<(), String> {
    #[cfg(windows)]
    {
        let (cli_path, _) = locate_bundled_binaries(app)?;
        run_elevated_windows(&cli_path, "uninstall")
    }

    #[cfg(not(windows))]
    {
        let _ = app;
        Err("Only available on Windows.".into())
    }
}

/// Registers `curb-app.exe` to start quietly in the taskbar tray on Windows login
/// using `HKCU\...\Run` (requires zero administrator privileges).
pub fn ensure_tray_autostart() {
    #[cfg(windows)]
    {
        use windows::core::PCWSTR;
        use windows::Win32::System::Registry::{
            RegCloseKey, RegOpenKeyExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER, KEY_SET_VALUE,
            REG_SZ,
        };

        let Ok(exe) = std::env::current_exe() else {
            return;
        };
        let subkey: Vec<u16> = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\0"
            .encode_utf16()
            .collect();
        let value_name: Vec<u16> = "Curb\0".encode_utf16().collect();
        let quoted_exe: Vec<u16> = format!("\"{}\"\0", exe.display())
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
}

#[cfg(windows)]
fn run_elevated_windows(exe: &PathBuf, params: &str) -> Result<(), String> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, HWND};
    use windows::Win32::System::Threading::WaitForSingleObject;
    use windows::Win32::UI::Shell::{
        ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
    };
    use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

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
