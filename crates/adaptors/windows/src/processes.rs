use std::collections::{HashMap, HashSet};
use std::path::Path;

use curb_core::adaptors::{BinaryVerifier, ProcessDiscoverer};
use curb_core::ipc::{BlockedEvent, RunningAppInfo};
use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, BOOL, HWND, LPARAM, RECT};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT,
    PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumChildWindows, EnumWindows, GetClassNameW, GetWindowLongW, GetWindowRect,
    GetWindowTextLengthW, GetWindowThreadProcessId, IsWindowVisible, GWL_EXSTYLE, WS_EX_APPWINDOW,
    WS_EX_TOOLWINDOW,
};

use crate::verify::WindowsBinaryVerifier;

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
    "applicationframehost.exe",
    "curb-service.exe",
    "curb-app.exe",
];

/// Windows ToolHelp32 + `EnumWindows` `ProcessDiscoverer`.
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsProcessDiscoverer;

impl ProcessDiscoverer for WindowsProcessDiscoverer {
    fn visible_window_pids(&self) -> Vec<u32> {
        let mut pids: Vec<u32> = enum_visible_window_pids().into_iter().collect();
        pids.sort_unstable();
        pids
    }

    fn collect_running_apps(
        &self,
        recent_blocked: &[BlockedEvent],
        caller_visible_pids: Option<&[u32]>,
    ) -> Vec<RunningAppInfo> {
        let visible_pids: HashSet<u32> = match caller_visible_pids {
            Some(pids) => pids.iter().copied().collect(),
            None => enum_visible_window_pids(),
        };
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
                    if pid > 4 {
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
                    }

                    if Process32NextW(snap, &mut entry).is_err() {
                        break;
                    }
                }
            }

            let _ = CloseHandle(snap);
        }

        let verifier = WindowsBinaryVerifier;
        let mut apps = Vec::new();
        for (path_str, (count, has_window)) in grouped {
            let path = Path::new(&path_str);
            let Ok(identity) = verifier.peek_binary(path) else {
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

            let signed = if identity.sha256.is_empty() {
                identity.signature.is_some()
            } else {
                identity.signature.as_ref().is_some_and(|s| s.trusted)
            };

            apps.push(RunningAppInfo {
                key: format!("run-{}", identity.path.to_ascii_lowercase()),
                name: display_name,
                exe: identity.filename,
                path: identity.path,
                process_count: count,
                background: !has_window,
                tried_connect: blocked_match.is_some(),
                tried_host: blocked_match.map(|b| b.destination.clone()),
                signed,
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

fn enum_visible_window_pids() -> HashSet<u32> {
    let mut pids = HashSet::new();

    unsafe extern "system" fn uwp_child_cb(hwnd: HWND, lparam: LPARAM) -> BOOL {
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

    unsafe extern "system" fn enum_cb(hwnd: HWND, lparam: LPARAM) -> BOOL {
        if !IsWindowVisible(hwnd).as_bool() {
            return BOOL(1);
        }

        let ex_style = GetWindowLongW(hwnd, GWL_EXSTYLE) as u32;
        if (ex_style & WS_EX_TOOLWINDOW.0) != 0 && (ex_style & WS_EX_APPWINDOW.0) == 0 {
            return BOOL(1);
        }

        let has_title = GetWindowTextLengthW(hwnd) > 0;
        let mut rect = RECT::default();
        let has_size = GetWindowRect(hwnd, &mut rect).is_ok()
            && rect.right > rect.left
            && rect.bottom > rect.top;
        if !has_title && !has_size {
            return BOOL(1);
        }

        let mut pid = 0u32;
        GetWindowThreadProcessId(hwnd, Some(&mut pid));
        if pid != 0 {
            let set = &mut *(lparam.0 as *mut HashSet<u32>);
            set.insert(pid);
        }

        let mut class_buf = [0u16; 64];
        let class_len = GetClassNameW(hwnd, &mut class_buf);
        if class_len > 0 {
            let class_name = String::from_utf16_lossy(&class_buf[..class_len as usize]);
            if class_name == "ApplicationFrameWindow" {
                let _ = EnumChildWindows(hwnd, Some(uwp_child_cb), lparam);
            }
        }

        BOOL(1)
    }

    unsafe {
        let _ = EnumWindows(Some(enum_cb), LPARAM(&mut pids as *mut _ as isize));
    }
    pids
}
