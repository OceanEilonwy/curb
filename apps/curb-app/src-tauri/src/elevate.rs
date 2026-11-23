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

#[cfg(windows)]
fn run_elevated_windows(exe: &PathBuf, params: &str) -> Result<(), String> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

    let verb: Vec<u16> = "runas\0".encode_utf16().collect();
    let file: Vec<u16> = OsStr::new(exe)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let args: Vec<u16> = params.encode_utf16().chain(std::iter::once(0)).collect();

    let res = unsafe {
        ShellExecuteW(
            HWND::default(),
            PCWSTR(verb.as_ptr()),
            PCWSTR(file.as_ptr()),
            PCWSTR(args.as_ptr()),
            PCWSTR::null(),
            SW_HIDE,
        )
    };

    // ShellExecuteW returns a value > 32 on success.
    if (res.0 as isize) <= 32 {
        return Err("Administrator approval was canceled or blocked.".into());
    }
    Ok(())
}
