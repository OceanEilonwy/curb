use std::path::{Path, PathBuf};

use curb_core::adaptors::{BinaryVerifier, SteamDiscoverer};
use curb_core::presets::{EffectiveRule, SteamPresetConfig};
use curb_core::steam::{
    collect_game_executables_with, discover_steam_games_with, is_windows_exe, DiscoveredSteamGame,
};
use curb_core::Result;
use windows::core::PCWSTR;
use windows::Win32::System::Registry::{
    RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE,
    KEY_READ, REG_SZ, REG_VALUE_TYPE,
};

use crate::verify::WindowsBinaryVerifier;

/// Windows Registry + `.exe` `SteamDiscoverer`.
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsSteamDiscoverer;

impl SteamDiscoverer for WindowsSteamDiscoverer {
    fn find_steam_root(&self) -> Option<PathBuf> {
        if let Some(path) = read_steam_path_from_registry() {
            if path.exists() {
                return Some(path);
            }
        }
        let default = PathBuf::from(r"C:\Program Files (x86)\Steam");
        if default.exists() {
            return Some(default);
        }
        None
    }

    fn discover_games(&self, steam_root: &Path) -> Result<Vec<DiscoveredSteamGame>> {
        let verifier = WindowsBinaryVerifier;
        discover_steam_games_with(steam_root, is_windows_exe, |p| verifier.peek_binary(p))
    }

    fn collect_game_executables(&self, game_dir: &Path) -> Vec<PathBuf> {
        collect_game_executables_with(game_dir, is_windows_exe)
    }

    fn steam_client_candidate_paths(&self, steam_root: &Path) -> Vec<PathBuf> {
        [
            "steam.exe",
            r"bin\steamservice.exe",
            r"bin\cef\cef.win7x64\steamwebhelper.exe",
            r"bin\cef\steamwebhelper.exe",
        ]
        .into_iter()
        .map(|rel| steam_root.join(rel))
        .filter(|p| p.exists())
        .collect()
    }

    fn expand_steam_preset(&self, preset: &SteamPresetConfig) -> Vec<EffectiveRule> {
        preset.expand_windows_rules()
    }
}

fn read_steam_path_from_registry() -> Option<PathBuf> {
    for (root, subkey_str, value_str) in [
        (
            HKEY_LOCAL_MACHINE,
            "SOFTWARE\\WOW6432Node\\Valve\\Steam\0",
            "InstallPath\0",
        ),
        (HKEY_CURRENT_USER, "Software\\Valve\\Steam\0", "SteamPath\0"),
    ] {
        let subkey: Vec<u16> = subkey_str.encode_utf16().collect();
        let value_name: Vec<u16> = value_str.encode_utf16().collect();

        unsafe {
            let mut hkey = HKEY::default();
            if RegOpenKeyExW(root, PCWSTR(subkey.as_ptr()), 0, KEY_READ, &mut hkey).is_err() {
                continue;
            }

            let mut buf = [0u16; 512];
            let mut buf_bytes = (buf.len() * 2) as u32;
            let mut kind = REG_VALUE_TYPE::default();
            let res = RegQueryValueExW(
                hkey,
                PCWSTR(value_name.as_ptr()),
                None,
                Some(&mut kind),
                Some(buf.as_mut_ptr() as *mut u8),
                Some(&mut buf_bytes),
            );
            let _ = RegCloseKey(hkey);

            if res.is_ok() && kind == REG_SZ {
                let char_len = (buf_bytes as usize / 2).min(buf.len());
                let path_str = String::from_utf16_lossy(&buf[..char_len])
                    .trim_end_matches('\0')
                    .replace('/', "\\");
                if !path_str.is_empty() {
                    return Some(PathBuf::from(path_str));
                }
            }
        }
    }
    None
}
