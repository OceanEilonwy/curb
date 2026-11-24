use std::fs;
use std::path::{Path, PathBuf};

use curb_core::adaptors::SteamDiscoverer;
use curb_core::steam::{collect_game_executables, discover_steam_games, DiscoveredSteamGame};
use curb_core::Result;

/// Linux `SteamDiscoverer` supporting native, Flatpak, Snap, and root `/home/*`
/// Steam libraries as well as native ELF and Proton `.exe` game binaries.
#[derive(Debug, Default, Clone, Copy)]
pub struct LinuxSteamDiscoverer;

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
        discover_steam_games(steam_root)
    }

    fn collect_game_executables(&self, game_dir: &Path) -> Vec<PathBuf> {
        collect_game_executables(game_dir)
    }
}
