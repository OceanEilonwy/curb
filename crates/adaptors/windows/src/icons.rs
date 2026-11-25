use std::collections::HashMap;
use std::ffi::{c_void, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use curb_core::adaptors::{AppIcon, AppIconRequest};
use curb_core::presets::{PresetHost, RegistryRoot};
use windows::core::PCWSTR;
use windows::Win32::Foundation::HWND;
use windows::Win32::Graphics::Gdi::{
    DeleteObject, GetDC, GetDIBits, GetObjectW, ReleaseDC, BITMAP, BITMAPINFO, BITMAPINFOHEADER,
    BI_RGB, DIB_RGB_COLORS, HBITMAP, HGDIOBJ,
};
use windows::Win32::UI::Shell::ExtractIconExW;
use windows::Win32::UI::WindowsAndMessaging::{DestroyIcon, GetIconInfo, HICON, ICONINFO};

use crate::preset_host::WindowsPresetHost;

static RESOLVED_CACHE: OnceLock<Mutex<HashMap<String, Option<AppIcon>>>> = OnceLock::new();

/// Resolves an application's embedded PE icon on Windows (the same source used by Task Manager).
pub fn resolve_app_icon(req: &AppIconRequest<'_>) -> Option<AppIcon> {
    let cache_key = format!(
        "{}|{}|{:?}",
        req.exe_path
            .map(|p| p.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default(),
        req.exe_name.unwrap_or_default().to_ascii_lowercase(),
        req.steam_app_id
    );

    let cache = RESOLVED_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(guard) = cache.lock() {
        if let Some(cached) = guard.get(&cache_key) {
            return cached.clone();
        }
    }

    let resolved = resolve_app_icon_uncached(req);

    if let Ok(mut guard) = cache.lock() {
        guard.insert(cache_key, resolved.clone());
    }

    resolved
}

fn resolve_app_icon_uncached(req: &AppIconRequest<'_>) -> Option<AppIcon> {
    let exe_path = locate_executable(req)?;
    extract_exe_icon_rgba(&exe_path)
}

fn locate_executable(req: &AppIconRequest<'_>) -> Option<PathBuf> {
    if let Some(p) = req.exe_path {
        if p.is_file() {
            return Some(p.to_path_buf());
        }
    }

    let exe_name = req.exe_name.map(|s| s.trim()).filter(|s| !s.is_empty())?;
    let exe_with_ext = if exe_name.to_ascii_lowercase().ends_with(".exe") {
        exe_name.to_string()
    } else {
        format!("{exe_name}.exe")
    };

    // Special case: Steam client executable via Steam registry keys
    if exe_with_ext.eq_ignore_ascii_case("steam.exe") {
        let host = WindowsPresetHost;
        for (root, subkey, value) in [
            (
                RegistryRoot::LocalMachine,
                r"SOFTWARE\WOW6432Node\Valve\Steam",
                "InstallPath",
            ),
            (RegistryRoot::CurrentUser, r"Software\Valve\Steam", "SteamPath"),
        ] {
            if let Some(dir) = host.read_windows_registry_string(root, subkey, value) {
                let candidate = PathBuf::from(dir.replace('/', "\\")).join("steam.exe");
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
        let default = PathBuf::from(r"C:\Program Files (x86)\Steam\steam.exe");
        if default.is_file() {
            return Some(default);
        }
    }

    // Check Windows App Paths registry (HKLM and HKCU)
    let host = WindowsPresetHost;
    let subkey = format!(
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{exe_with_ext}"
    );
    for root in [RegistryRoot::LocalMachine, RegistryRoot::CurrentUser] {
        if let Some(raw) = host.read_windows_registry_string(root, &subkey, "") {
            let cleaned = raw.trim().trim_matches('"');
            let p = PathBuf::from(cleaned);
            if p.is_file() {
                return Some(p);
            }
        }
    }

    // Check PATH directories
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join(&exe_with_ext);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }

    None
}

/// Extracts the primary embedded icon from a Windows PE executable and converts it
/// into a straight-alpha RGBA8 pixel buffer.
fn extract_exe_icon_rgba(exe_path: &Path) -> Option<AppIcon> {
    let wide_path: Vec<u16> = OsStr::new(exe_path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let mut hicon = HICON::default();
        let count = ExtractIconExW(
            PCWSTR(wide_path.as_ptr()),
            0,
            Some(&mut hicon),
            None,
            1,
        );
        if count == 0 || hicon.is_invalid() || hicon.0.is_null() {
            // Fallback to small icon if no large icon was returned
            let count_small = ExtractIconExW(
                PCWSTR(wide_path.as_ptr()),
                0,
                None,
                Some(&mut hicon),
                1,
            );
            if count_small == 0 || hicon.is_invalid() || hicon.0.is_null() {
                return None;
            }
        }

        let result = hicon_to_rgba(hicon);
        let _ = DestroyIcon(hicon);
        result
    }
}

unsafe fn hicon_to_rgba(hicon: HICON) -> Option<AppIcon> {
    let mut info = ICONINFO::default();
    if GetIconInfo(hicon, &mut info).is_err() {
        return None;
    }

    let cleanup = |info: &ICONINFO| {
        if !info.hbmColor.is_invalid() && !info.hbmColor.0.is_null() {
            let _ = DeleteObject(HGDIOBJ(info.hbmColor.0));
        }
        if !info.hbmMask.is_invalid() && !info.hbmMask.0.is_null() {
            let _ = DeleteObject(HGDIOBJ(info.hbmMask.0));
        }
    };

    let has_color = !info.hbmColor.is_invalid() && !info.hbmColor.0.is_null();
    if !has_color {
        cleanup(&info);
        return None;
    }

    let mut bmp = BITMAP::default();
    let got = GetObjectW(
        HGDIOBJ(info.hbmColor.0),
        std::mem::size_of::<BITMAP>() as i32,
        Some(&mut bmp as *mut BITMAP as *mut c_void),
    );
    if got == 0 || bmp.bmWidth <= 0 || bmp.bmHeight <= 0 {
        cleanup(&info);
        return None;
    }

    let width = bmp.bmWidth as u32;
    let height = bmp.bmHeight as u32;
    let pixel_count = (width as usize).checked_mul(height as usize)?;
    let byte_len = pixel_count.checked_mul(4)?;

    let hdc = GetDC(HWND::default());
    if hdc.is_invalid() || hdc.0.is_null() {
        cleanup(&info);
        return None;
    }

    let mut bgra = vec![0u8; byte_len];
    let ok_color = read_bitmap_bgra(hdc, info.hbmColor, width, height, &mut bgra);
    if !ok_color {
        let _ = ReleaseDC(HWND::default(), hdc);
        cleanup(&info);
        return None;
    }

    // Legacy icons store all-zero alpha in hbmColor and rely on the AND mask (hbmMask).
    let has_any_alpha = bgra.chunks_exact(4).any(|px| px[3] != 0);
    if !has_any_alpha && !info.hbmMask.is_invalid() && !info.hbmMask.0.is_null() {
        let mut mask_bgra = vec![0u8; byte_len];
        if read_bitmap_bgra(hdc, info.hbmMask, width, height, &mut mask_bgra) {
            for (px, mask_px) in bgra.chunks_exact_mut(4).zip(mask_bgra.chunks_exact(4)) {
                // In Windows icon AND mask, 0 (black) = opaque pixel, 255 (white) = transparent.
                px[3] = if mask_px[0] == 0 { 255 } else { 0 };
            }
        } else {
            for px in bgra.chunks_exact_mut(4) {
                px[3] = 255;
            }
        }
    }

    let _ = ReleaseDC(HWND::default(), hdc);
    cleanup(&info);

    // Convert BGRA -> RGBA
    let mut rgba = Vec::with_capacity(byte_len);
    for px in bgra.chunks_exact(4) {
        rgba.push(px[2]);
        rgba.push(px[1]);
        rgba.push(px[0]);
        rgba.push(px[3]);
    }

    Some(AppIcon::Rgba {
        width,
        height,
        data: rgba,
    })
}

unsafe fn read_bitmap_bgra(
    hdc: windows::Win32::Graphics::Gdi::HDC,
    hbm: HBITMAP,
    width: u32,
    height: u32,
    out_bgra: &mut [u8],
) -> bool {
    let mut bmi = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: width as i32,
            biHeight: -(height as i32), // top-down DIB
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB.0,
            ..Default::default()
        },
        ..Default::default()
    };

    let scanlines = GetDIBits(
        hdc,
        hbm,
        0,
        height,
        Some(out_bgra.as_mut_ptr() as *mut c_void),
        &mut bmi,
        DIB_RGB_COLORS,
    );
    scanlines != 0
}
