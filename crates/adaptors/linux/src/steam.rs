use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use curb_core::adaptors::SteamDiscoverer;
use curb_core::presets::{EffectiveRule, SteamPresetConfig};
use curb_core::steam::{
    collect_game_executables_with, discover_steam_games_with, is_windows_exe, DiscoveredSteamGame,
};
use curb_core::verify::peek_binary;
use curb_core::Result;

/// Linux `SteamDiscoverer` supporting native, Flatpak, Snap, and root `/home/*`
/// Steam libraries as well as native ELF and Proton `.exe` game binaries.
#[derive(Debug, Default, Clone, Copy)]
pub struct LinuxSteamDiscoverer;

/// Returns true if `path` is either a Proton/Wine `.exe` or an executable Linux ELF binary.
pub fn is_linux_game_executable(path: &Path) -> bool {
    if is_windows_exe(path) {
        return true;
    }
    let Some(name_lower) = path
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
    else {
        return false;
    };
    if name_lower.contains(".so") || name_lower.ends_with(".sh") || name_lower.ends_with(".py") {
        return false;
    }
    let Ok(meta) = fs::metadata(path) else {
        return false;
    };
    if meta.permissions().mode() & 0o111 == 0 {
        return false;
    }
    let Ok(mut f) = fs::File::open(path) else {
        return false;
    };
    let mut magic = [0u8; 4];
    f.read_exact(&mut magic).is_ok() && magic == *b"\x7fELF"
}

impl SteamDiscoverer for LinuxSteamDiscoverer {
    fn find_steam_root(&self) -> Option<PathBuf> {
        let mut home_dirs = Vec::new();
        if let Ok(home) = std::env::var("HOME") {
            home_dirs.push(PathBuf::from(home));
        }
        if let Ok(entries) = fs::read_dir("/home") {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_dir() && !home_dirs.contains(&p) {
                    home_dirs.push(p);
                }
            }
        }

        for home in home_dirs {
            let candidates = [
                home.join(".local/share/Steam"),
                home.join(".steam/steam"),
                home.join(".steam/debian-installation"),
                home.join(".var/app/com.valvesoftware.Steam/.local/share/Steam"),
                home.join("snap/steam/common/.local/share/Steam"),
            ];
            for c in candidates {
                if c.join("steamapps").exists() {
                    return Some(c);
                }
            }
        }
        None
    }

    fn discover_games(&self, steam_root: &Path) -> Result<Vec<DiscoveredSteamGame>> {
        discover_steam_games_with(steam_root, is_linux_game_executable, peek_binary)
    }

    fn collect_game_executables(&self, game_dir: &Path) -> Vec<PathBuf> {
        collect_game_executables_with(game_dir, is_linux_game_executable)
    }

    fn steam_client_candidate_paths(&self, steam_root: &Path) -> Vec<PathBuf> {
        [
            "ubuntu12_32/steam",
            "ubuntu12_64/steamwebhelper",
        ]
        .into_iter()
        .map(|rel| steam_root.join(rel))
        .filter(|p| p.exists())
        .collect()
    }

    fn expand_steam_preset(&self, preset: &SteamPresetConfig) -> Vec<EffectiveRule> {
        preset.expand_linux_rules()
    }
}
