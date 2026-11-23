use curb_core::ipc::{BlockedEvent, RunningAppInfo};

/// Enumerates currently running applications grouped by executable path
/// (Activity Monitor / Task Manager style), separating foreground windowed
/// apps from background processes and annotating apps that recently tried
/// to go online.
pub fn collect_running_apps(recent_blocked: &[BlockedEvent]) -> Vec<RunningAppInfo> {
    #[cfg(windows)]
    {
        windows_impl::collect(recent_blocked)
    }

    #[cfg(not(windows))]
    {
        let _ = recent_blocked;
        Vec::new()
    }
}

#[cfg(windows)]
mod windows_impl {
    use std::collections::{HashMap, HashSet};
    use std::path::Path;

    use curb_core::ipc::{BlockedEvent, RunningAppInfo};
    use curb_core::verify::inspect_binary;
    use windows::core::PWSTR;
    use windows::Win32::Foundation::{BOOL, CloseHandle, HWND, LPARAM};
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        EnumWindows, GetWindowThreadProcessId, IsWindowVisible,
    };

    const SYSTEM_EXCLUDED: &[&str] = &[
        "svchost.exe",
        "csrss.exe",
        "smss.exe",
        "wininit.exe",
        "winlogon.exe",
        "services.exe",
        "lsass.exe",
        "dwm.exe",
        "explorer.exe",
        "taskhostw.exe",
        "sihost.exe",
        "runtimebroker.exe",
        "searchhost.exe",
        "ctfmon.exe",
        "conhost.exe",
        "curb-service.exe",
        "curb-app.exe",
    ];

    pub fn collect(recent_blocked: &[BlockedEvent]) -> Vec<RunningAppInfo> {
        let visible_pids = visible_window_pids();
        let mut grouped: HashMap<String, (u32, bool)> = HashMap::new();

        unsafe {
            let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
                return Vec::new();
            };

            let mut entry = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };

            if Process32FirstW(snap, &mut entry).is_ok() {
                loop {
                    let pid = entry.th32ProcessID;
                    if let Some(full_path) = query_process_path(pid) {
                        let exe_lower = Path::new(&full_path)
                            .file_name()
                            .map(|f| f.to_string_lossy().to_ascii_lowercase())
                            .unwrap_or_default();

                        if !SYSTEM_EXCLUDED.contains(&exe_lower.as_str()) {
                            let is_fg = visible_pids.contains(&pid);
                            let slot = grouped.entry(full_path).or_insert((0, false));
                            slot.0 += 1;
                            slot.1 = slot.1 || is_fg;
                        }
                    }

                    if Process32NextW(snap, &mut entry).is_err() {
                        break;
                    }
                }
            }

            let _ = CloseHandle(snap);
        }

        let mut apps = Vec::new();
        for (path_str, (count, has_window)) in grouped {
            let path = Path::new(&path_str);
            let Ok(identity) = inspect_binary(path) else {
                continue;
            };
            let display_name = identity
                .product_name
                .clone()
                .or_else(|| identity.file_description.clone())
                .unwrap_or_else(|| {
                    identity
                        .filename
                        .strip_suffix(".exe")
                        .or_else(|| identity.filename.strip_suffix(".EXE"))
                        .unwrap_or(&identity.filename)
                        .to_string()
                });

            let blocked_match = recent_blocked
                .iter()
                .find(|b| b.exe.eq_ignore_ascii_case(&identity.filename));

            apps.push(RunningAppInfo {
                key: format!("run-{}", identity.path.to_ascii_lowercase()),
                name: display_name,
                exe: identity.filename,
                path: identity.path,
                process_count: count,
                background: !has_window,
                tried_connect: blocked_match.is_some(),
                tried_host: blocked_match.map(|b| b.destination.clone()),
                signed: identity.signature.as_ref().is_some_and(|s| s.trusted),
                signer: identity.signature.map(|s| s.subject_cn),
                sha256: identity.sha256,
            });
        }

        apps.sort_by(|a, b| {
            b.tried_connect
                .cmp(&a.tried_connect)
                .then_with(|| a.background.cmp(&b.background))
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        apps
    }

    unsafe fn query_process_path(pid: u32) -> Option<String> {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_FORMAT(0),
            PWSTR(buf.as_mut_ptr()),
            &mut len,
        );
        let _ = CloseHandle(handle);
        if ok.is_ok() && len > 0 {
            Some(String::from_utf16_lossy(&buf[..len as usize]))
        } else {
            None
        }
    }

    fn visible_window_pids() -> HashSet<u32> {
        let mut pids = HashSet::new();
        unsafe extern "system" fn enum_cb(hwnd: HWND, lparam: LPARAM) -> BOOL {
            if IsWindowVisible(hwnd).as_bool() {
                let mut pid = 0u32;
                GetWindowThreadProcessId(hwnd, Some(&mut pid));
                if pid != 0 {
                    let set = &mut *(lparam.0 as *mut HashSet<u32>);
                    set.insert(pid);
                }
            }
            BOOL(1)
        }
        unsafe {
            let _ = EnumWindows(Some(enum_cb), LPARAM(&mut pids as *mut _ as isize));
        }
        pids
    }
}
