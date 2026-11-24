use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::verify::{peek_binary, BinaryIdentity};
use crate::Result;

/// A Steam game discovered from `libraryfolders.vdf` + `appmanifest_<appid>.acf`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoveredSteamGame {
    pub app_id: u32,
    pub name: String,
    pub install_dir: PathBuf,
    pub exe_path: PathBuf,
    pub exe_name: String,
    pub signed: bool,
    pub signer: Option<String>,
    pub sha256: String,
}

/// Filenames (lowercased substrings) skipped when picking the primary game executable.
const IGNORED_EXE_PATTERNS: &[&str] = &[
    "vcredist",
    "dxsetup",
    "dotnetfx",
    "ndp4",
    "oalinst",
    "physx",
    "crashhandler",
    "crashreport",
    "unitycrashhandler",
    "ue4prereq",
    "ueprereq",
    "unins000",
    "uninstall",
    "cleanup",
    "touchup",
    "directx",
    "redist",
    "easyanticheat_setup",
];

/// Subdirectory names (lowercased) skipped during recursive executable search to avoid
/// traversing huge non-executable game asset trees.
const IGNORED_DIR_NAMES: &[&str] = &[
    "_commonredist",
    "directx",
    "redist",
    "locales",
    "shaders",
    "textures",
    "audio",
    "sounds",
    "music",
    "movies",
    "videos",
    "fonts",
    "paks",
    "logs",
    "screenshots",
];

/// Parses Steam's `libraryfolders.vdf` content and returns all library root paths.
pub fn parse_library_folders_vdf(vdf: &str) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for line in vdf.lines() {
        let tokens = extract_quoted_tokens(line);
        if tokens.len() >= 2 {
            let key = tokens[0].to_ascii_lowercase();
            // Modern Steam uses `"path" "D:\\SteamLibrary"`.
            // Legacy Steam used numeric keys `"1" "D:\\SteamLibrary"`.
            if key == "path"
                || (key.chars().all(|c| c.is_ascii_digit())
                    && (tokens[1].contains('\\') || tokens[1].starts_with('/')))
            {
                let unescaped = tokens[1].replace("\\\\", "\\");
                let candidate = PathBuf::from(unescaped);
                if !paths.contains(&candidate) {
                    paths.push(candidate);
                }
            }
        }
    }
    paths
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppManifest {
    pub app_id: u32,
    pub name: String,
    pub install_dir: String,
}

/// Parses a Steam `appmanifest_<appid>.acf` file for app ID, title, and install folder.
pub fn parse_app_manifest_acf(acf: &str) -> Option<AppManifest> {
    let mut app_id = None;
    let mut name = None;
    let mut install_dir = None;

    for line in acf.lines() {
        let tokens = extract_quoted_tokens(line);
        if tokens.len() >= 2 {
            match tokens[0].to_ascii_lowercase().as_str() {
                "appid" => app_id = tokens[1].parse::<u32>().ok(),
                "name" => name = Some(tokens[1].clone()),
                "installdir" => install_dir = Some(tokens[1].clone()),
                _ => {}
            }
        }
    }

    Some(AppManifest {
        app_id: app_id?,
        name: name?,
        install_dir: install_dir?,
    })
}

/// Pure-Rust filename predicate matching Windows PE `.exe` binaries.
pub fn is_windows_exe(path: &Path) -> bool {
    path.file_name()
        .is_some_and(|n| n.to_string_lossy().to_ascii_lowercase().ends_with(".exe"))
}

/// Scans a Steam installation root and all secondary library folders for installed games,
/// using OS-adaptor callbacks for executable detection (`is_executable`) and metadata
/// inspection (`peek_fn`).
pub fn discover_steam_games_with<F, P>(
    steam_root: &Path,
    is_executable: F,
    peek_fn: P,
) -> Result<Vec<DiscoveredSteamGame>>
where
    F: Fn(&Path) -> bool,
    P: Fn(&Path) -> Result<BinaryIdentity>,
{
    let mut library_roots = vec![steam_root.to_path_buf()];

    let vdf_path = steam_root.join("steamapps").join("libraryfolders.vdf");
    if let Ok(vdf) = fs::read_to_string(&vdf_path) {
        for lib in parse_library_folders_vdf(&vdf) {
            if !library_roots.contains(&lib) {
                library_roots.push(lib);
            }
        }
    }

    let mut games = Vec::new();
    for lib_root in library_roots {
        let steamapps = lib_root.join("steamapps");
        let Ok(entries) = fs::read_dir(&steamapps) else {
            continue;
        };

        for entry in entries.flatten() {
            let file_name = entry.file_name().to_string_lossy().to_string();
            if !file_name.starts_with("appmanifest_") || !file_name.ends_with(".acf") {
                continue;
            }
            let Ok(content) = fs::read_to_string(entry.path()) else {
                continue;
            };
            let Some(manifest) = parse_app_manifest_acf(&content) else {
                continue;
            };

            // Skip Steamworks Common Redistributables (228980)
            if manifest.app_id == 228980 {
                continue;
            }

            let game_dir = steamapps.join("common").join(&manifest.install_dir);
            if let Some(exe_path) = pick_primary_executable_with(&game_dir, &is_executable) {
                if let Ok(identity) = peek_fn(&exe_path) {
                    let signed = if identity.sha256.is_empty() {
                        identity.signature.is_some()
                    } else {
                        identity.signature.as_ref().is_some_and(|s| s.trusted)
                    };
                    games.push(DiscoveredSteamGame {
                        app_id: manifest.app_id,
                        name: manifest.name,
                        install_dir: game_dir,
                        exe_path,
                        exe_name: identity.filename,
                        signed,
                        signer: identity.signature.map(|s| s.subject_cn),
                        sha256: identity.sha256,
                    });
                }
            }
        }
    }

    games.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    Ok(games)
}

/// Pure-Rust default Steam game scanner (matches `.exe` binaries without OS signature peeks).
pub fn discover_steam_games(steam_root: &Path) -> Result<Vec<DiscoveredSteamGame>> {
    discover_steam_games_with(steam_root, is_windows_exe, peek_binary)
}

/// Finds the most likely primary game binary inside `game_dir` (up to depth 3),
/// filtering out common redistributables and crash reporters, preferring Unreal Engine
/// `-Shipping.exe` binaries, then shallower depth, then larger file size.
pub fn pick_primary_executable_with<F>(game_dir: &Path, is_executable: &F) -> Option<PathBuf>
where
    F: Fn(&Path) -> bool,
{
    let mut candidates: Vec<(u64, usize, PathBuf)> = Vec::new();
    collect_exes(game_dir, 0, 3, is_executable, &mut candidates);

    candidates.sort_by(|a, b| {
        let a_shipping = a
            .2
            .file_name()
            .is_some_and(|n| n.to_string_lossy().to_ascii_lowercase().ends_with("-shipping.exe"));
        let b_shipping = b
            .2
            .file_name()
            .is_some_and(|n| n.to_string_lossy().to_ascii_lowercase().ends_with("-shipping.exe"));
        b_shipping
            .cmp(&a_shipping)
            .then_with(|| a.1.cmp(&b.1))
            .then_with(|| b.0.cmp(&a.0))
    });
    candidates.into_iter().next().map(|(_, _, path)| path)
}

/// Pure-Rust default primary `.exe` picker.
pub fn pick_primary_executable(game_dir: &Path) -> Option<PathBuf> {
    pick_primary_executable_with(game_dir, &is_windows_exe)
}

/// Collects all non-ignored game executables inside `game_dir` (up to depth 3)
/// matching the OS-adaptor predicate `is_executable`.
pub fn collect_game_executables_with<F>(game_dir: &Path, is_executable: F) -> Vec<PathBuf>
where
    F: Fn(&Path) -> bool,
{
    let mut candidates: Vec<(u64, usize, PathBuf)> = Vec::new();
    collect_exes(game_dir, 0, 3, &is_executable, &mut candidates);
    candidates.into_iter().map(|(_, _, path)| path).collect()
}

/// Pure-Rust default `.exe` collector.
pub fn collect_game_executables(game_dir: &Path) -> Vec<PathBuf> {
    collect_game_executables_with(game_dir, is_windows_exe)
}

fn collect_exes<F>(
    dir: &Path,
    depth: usize,
    max_depth: usize,
    is_executable: &F,
    out: &mut Vec<(u64, usize, PathBuf)>,
) where
    F: Fn(&Path) -> bool,
{
    if depth > max_depth {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };

    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            if depth < max_depth {
                let dir_lower = entry.file_name().to_string_lossy().to_ascii_lowercase();
                if !IGNORED_DIR_NAMES.contains(&dir_lower.as_str()) {
                    collect_exes(&entry.path(), depth + 1, max_depth, is_executable, out);
                }
            }
        } else if file_type.is_file() {
            let path = entry.path();
            let name_lower = entry.file_name().to_string_lossy().to_ascii_lowercase();
            if !is_executable(&path) {
                continue;
            }
            if IGNORED_EXE_PATTERNS.iter().any(|p| name_lower.contains(p)) {
                continue;
            }
            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
            out.push((size, depth, path));
        }
    }
}

fn extract_quoted_tokens(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '"' {
            let mut val = String::new();
            while let Some(nc) = chars.next() {
                if nc == '"' {
                    break;
                }
                if nc == '\\' {
                    if let Some(&next) = chars.peek() {
                        if next == '"' || next == '\\' {
                            val.push(chars.next().unwrap());
                            continue;
                        }
                    }
                }
                val.push(nc);
            }
            tokens.push(val);
        }
    }
    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_modern_libraryfolders_vdf() {
        let vdf = r#"
"libraryfolders"
{
    "0"
    {
        "path"      "C:\\Program Files (x86)\\Steam"
        "label"     ""
    }
    "1"
    {
        "path"      "D:\\SteamLibrary"
        "label"     "Games"
    }
}
"#;
        let libs = parse_library_folders_vdf(vdf);
        assert_eq!(libs.len(), 2);
        assert_eq!(libs[0], PathBuf::from(r"C:\Program Files (x86)\Steam"));
        assert_eq!(libs[1], PathBuf::from(r"D:\SteamLibrary"));
    }

    #[test]
    fn parses_app_manifest_acf() {
        let acf = r#"
"AppState"
{
    "appid"         "1145350"
    "name"          "Hades II"
    "installdir"    "Hades II"
}
"#;
        let manifest = parse_app_manifest_acf(acf).expect("manifest");
        assert_eq!(manifest.app_id, 1145350);
        assert_eq!(manifest.name, "Hades II");
        assert_eq!(manifest.install_dir, "Hades II");
    }

    #[test]
    fn discovers_game_skipping_crash_handler() {
        let tmp = std::env::temp_dir().join(format!("curb_steam_test_{}", uuid::Uuid::new_v4()));
        let common = tmp.join("steamapps/common/Hades II");
        fs::create_dir_all(&common).unwrap();
        fs::write(
            tmp.join("steamapps/appmanifest_1145350.acf"),
            "\"AppState\" {\n \"appid\" \"1145350\"\n \"name\" \"Hades II\"\n \"installdir\" \"Hades II\"\n}",
        )
        .unwrap();
        fs::write(common.join("UnityCrashHandler64.exe"), vec![0u8; 5000]).unwrap();
        fs::write(common.join("Hades2.exe"), vec![1u8; 2000]).unwrap();

        let games = discover_steam_games(&tmp).unwrap();
        assert_eq!(games.len(), 1);
        assert_eq!(games[0].name, "Hades II");
        assert_eq!(games[0].exe_name, "Hades2.exe");

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn skips_ignored_dirs_and_finds_nested_game_binary() {
        let tmp = std::env::temp_dir().join(format!("curb_steam_dirs_{}", uuid::Uuid::new_v4()));
        let redist = tmp.join("_CommonRedist");
        let bin = tmp.join("Binaries/Win64");
        fs::create_dir_all(&redist).unwrap();
        fs::create_dir_all(&bin).unwrap();
        fs::write(redist.join("HelperTool.exe"), vec![0u8; 50_000]).unwrap();
        fs::write(bin.join("Game-Win64-Shipping.exe"), vec![1u8; 2_000]).unwrap();

        let picked = pick_primary_executable(&tmp).expect("picked exe");
        assert_eq!(
            picked.file_name().unwrap().to_string_lossy(),
            "Game-Win64-Shipping.exe"
        );

        let _ = fs::remove_dir_all(&tmp);
    }
}
