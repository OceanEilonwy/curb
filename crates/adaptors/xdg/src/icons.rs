use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use curb_core::adaptors::{AppIcon, AppIconRequest};

/// Supported icon image extensions that Slint can decode directly.
const ICON_EXTENSIONS: &[&str] = &["png", "svg"];

/// Standard Freedesktop `<size>/<context>` directories ordered by crispness for 24-36px UI badges.
const SIZE_FIRST_DIRS: &[&str] = &[
    "48x48/apps",
    "32x32/apps",
    "64x64/apps",
    "128x128/apps",
    "256x256/apps",
    "scalable/apps",
    "24x24/apps",
    "22x22/apps",
    "16x16/apps",
    // Secondary contexts used by some system/utility apps
    "48x48/categories",
    "32x32/categories",
    "scalable/categories",
    "48x48/devices",
    "32x32/devices",
    "scalable/devices",
    "48x48/places",
    "32x32/places",
    "scalable/places",
];

/// KDE Breeze-style `<context>/<size>` directories (e.g. `/usr/share/icons/breeze/apps/48/konsole.svg`).
const CONTEXT_FIRST_DIRS: &[&str] = &[
    "apps/48",
    "apps/32",
    "apps/64",
    "apps/scalable",
    "apps/24",
    "apps/22",
    "apps/16",
    "categories/48",
    "categories/32",
    "devices/48",
    "devices/32",
    "places/48",
    "places/32",
];

#[derive(Debug, Default)]
struct DesktopIconIndex {
    by_exec_path: HashMap<String, String>,
    by_exec_name: HashMap<String, String>,
    by_app_name: HashMap<String, String>,
    by_stem: HashMap<String, String>,
}

#[derive(Debug, Clone)]
struct ParsedDesktopIconEntry {
    name: Option<String>,
    exec_path: Option<String>,
    exec_names: Vec<String>,
    wm_class: Option<String>,
    icon: String,
    no_display: bool,
}

static DESKTOP_INDEX: OnceLock<DesktopIconIndex> = OnceLock::new();
static THEME_CHAIN: OnceLock<Vec<String>> = OnceLock::new();
static ICON_BASE_DIRS: OnceLock<Vec<PathBuf>> = OnceLock::new();
static RESOLVED_CACHE: OnceLock<Mutex<HashMap<String, Option<PathBuf>>>> = OnceLock::new();

/// Resolves an application icon on Linux using `.desktop` entries and the Freedesktop Icon Theme
/// specification (the same mechanism used by KDE System Monitor and GNOME System Monitor).
pub fn resolve_app_icon(req: &AppIconRequest<'_>) -> Option<AppIcon> {
    let cache_key = format!(
        "{}|{}|{}|{:?}",
        req.exe_path
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default(),
        req.exe_name.unwrap_or_default(),
        req.app_name.unwrap_or_default(),
        req.steam_app_id
    );

    let cache = RESOLVED_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(guard) = cache.lock() {
        if let Some(cached) = guard.get(&cache_key) {
            return cached.clone().map(AppIcon::Path);
        }
    }

    let resolved = resolve_app_icon_uncached(req);

    if let Ok(mut guard) = cache.lock() {
        guard.insert(cache_key, resolved.clone());
    }

    resolved.map(AppIcon::Path)
}

fn resolve_app_icon_uncached(req: &AppIconRequest<'_>) -> Option<PathBuf> {
    let index = DESKTOP_INDEX.get_or_init(build_desktop_icon_index);
    let themes = THEME_CHAIN.get_or_init(detect_icon_theme_chain);
    let base_dirs = ICON_BASE_DIRS.get_or_init(icon_base_dirs);

    let candidates = collect_icon_candidates(req, index);
    for candidate in &candidates {
        if let Some(path) = lookup_icon_in_themes(candidate, themes, base_dirs) {
            return Some(path);
        }
    }

    // Steam library cache fallback for installed Steam games without a desktop shortcut icon.
    if let Some(app_id) = req.steam_app_id {
        if let Some(path) = find_steam_library_cache_icon(app_id) {
            return Some(path);
        }
    }

    None
}

fn collect_icon_candidates(req: &AppIconRequest<'_>, index: &DesktopIconIndex) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut push = |val: &str| {
        let trimmed = val.trim();
        if !trimmed.is_empty() && seen.insert(trimmed.to_string()) {
            out.push(trimmed.to_string());
        }
    };

    // 1. Steam AppID XDG icon name (e.g. `steam_icon_730` installed by Steam in hicolor)
    if let Some(app_id) = req.steam_app_id {
        push(&format!("steam_icon_{app_id}"));
    }

    // 2. Match `.desktop` entries by full executable path (and canonical path if symlink)
    if let Some(exe_path) = req.exe_path {
        let path_str = exe_path.to_string_lossy();
        if let Some(icon) = index.by_exec_path.get(path_str.as_ref()) {
            push(icon);
        }
        if let Ok(canon) = fs::canonicalize(exe_path) {
            let canon_str = canon.to_string_lossy();
            if let Some(icon) = index.by_exec_path.get(canon_str.as_ref()) {
                push(icon);
            }
        }
        // Snap paths: `/snap/<snap-name>/<rev>/...`
        if let Some(snap_name) = extract_snap_name(exe_path) {
            if let Some(icon) = index.by_exec_name.get(&snap_name) {
                push(icon);
            }
            if let Some(icon) = index.by_stem.get(&snap_name) {
                push(icon);
            }
        }
    }

    // 3. Match `.desktop` entries by executable basename (and stripped variants like `-bin`, `.exe`)
    let mut exe_variants = Vec::new();
    if let Some(name) = req.exe_name {
        collect_exe_variants(name, &mut exe_variants);
    }
    if let Some(path_name) = req
        .exe_path
        .and_then(|p| p.file_name())
        .map(|f| f.to_string_lossy().into_owned())
    {
        collect_exe_variants(&path_name, &mut exe_variants);
    }

    for v in &exe_variants {
        if let Some(icon) = index.by_exec_name.get(v) {
            push(icon);
        }
        if let Some(icon) = index.by_stem.get(v) {
            push(icon);
        }
    }

    // 4. Match `.desktop` entries by display name
    if let Some(app_name) = req.app_name {
        let lower = app_name.trim().to_ascii_lowercase();
        if let Some(icon) = index.by_app_name.get(&lower) {
            push(icon);
        }
        if let Some(icon) = index.by_stem.get(&lower) {
            push(icon);
        }
    }

    // 5. Direct theme lookup by executable name (KDE System Monitor `QIcon::fromTheme` fallback)
    for v in &exe_variants {
        push(v);
    }
    if let Some(app_name) = req.app_name {
        let slug = app_name
            .trim()
            .to_ascii_lowercase()
            .replace(' ', "-");
        if !slug.is_empty() {
            push(&slug);
        }
    }

    out
}

fn collect_exe_variants(raw: &str, out: &mut Vec<String>) {
    let base = Path::new(raw)
        .file_name()
        .map(|f| f.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_else(|| raw.to_ascii_lowercase());
    let base = base.trim().to_string();
    if base.is_empty() {
        return;
    }
    if !out.contains(&base) {
        out.push(base.clone());
    }
    for suffix in [
        ".exe", "-bin", ".bin", ".sh", "-wrapped", "-esr", "-stable", "-browser",
    ] {
        if let Some(stripped) = base.strip_suffix(suffix) {
            if !stripped.is_empty() && !out.iter().any(|s| s == stripped) {
                out.push(stripped.to_string());
            }
        }
    }
}

fn extract_snap_name(path: &Path) -> Option<String> {
    let mut comps = path.components();
    let first = comps.next()?.as_os_str().to_str()?;
    if first != "/" {
        return None;
    }
    let second = comps.next()?.as_os_str().to_str()?;
    if second != "snap" {
        return None;
    }
    let name = comps.next()?.as_os_str().to_str()?;
    Some(name.to_ascii_lowercase())
}

fn desktop_application_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(xdg_home) = std::env::var("XDG_DATA_HOME") {
        if !xdg_home.is_empty() {
            dirs.push(PathBuf::from(xdg_home).join("applications"));
        }
    } else if let Ok(home) = std::env::var("HOME") {
        dirs.push(PathBuf::from(&home).join(".local/share/applications"));
    }

    if let Ok(home) = std::env::var("HOME") {
        dirs.push(PathBuf::from(home).join(".local/share/flatpak/exports/share/applications"));
    }

    if let Ok(xdg_dirs) = std::env::var("XDG_DATA_DIRS") {
        for dir in xdg_dirs.split(':').filter(|s| !s.is_empty()) {
            dirs.push(PathBuf::from(dir).join("applications"));
        }
    } else {
        dirs.push(PathBuf::from("/usr/local/share/applications"));
        dirs.push(PathBuf::from("/usr/share/applications"));
    }

    dirs.push(PathBuf::from("/var/lib/flatpak/exports/share/applications"));
    dirs.push(PathBuf::from("/var/lib/snapd/desktop/applications"));
    dirs
}

fn build_desktop_icon_index() -> DesktopIconIndex {
    build_desktop_icon_index_from_dirs(&desktop_application_dirs())
}

fn build_desktop_icon_index_from_dirs(dirs: &[PathBuf]) -> DesktopIconIndex {
    let mut index = DesktopIconIndex::default();
    let mut deferred_hidden: Vec<(String, ParsedDesktopIconEntry)> = Vec::new();

    for dir in dirs {
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("desktop") {
                continue;
            }
            let Ok(content) = fs::read_to_string(&path) else {
                continue;
            };
            let Some(parsed) = parse_desktop_icon_entry(&content) else {
                continue;
            };
            let stem = path
                .file_stem()
                .map(|s| s.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default();

            if parsed.no_display {
                deferred_hidden.push((stem, parsed));
            } else {
                insert_desktop_entry(&mut index, &stem, parsed);
            }
        }
    }

    // Insert NoDisplay=true entries only where no visible entry already claimed the key.
    for (stem, parsed) in deferred_hidden {
        insert_desktop_entry(&mut index, &stem, parsed);
    }

    index
}

fn insert_desktop_entry(
    index: &mut DesktopIconIndex,
    stem: &str,
    entry: ParsedDesktopIconEntry,
) {
    if let Some(exec_path) = entry.exec_path {
        index
            .by_exec_path
            .entry(exec_path)
            .or_insert_with(|| entry.icon.clone());
    }
    for name in entry.exec_names {
        index
            .by_exec_name
            .entry(name)
            .or_insert_with(|| entry.icon.clone());
    }
    if let Some(app_name) = entry.name {
        index
            .by_app_name
            .entry(app_name.to_ascii_lowercase())
            .or_insert_with(|| entry.icon.clone());
    }
    if !stem.is_empty() {
        index
            .by_stem
            .entry(stem.to_string())
            .or_insert_with(|| entry.icon.clone());
        // Also index reverse-DNS suffix (e.g. `org.kde.konsole` -> `konsole`).
        if let Some(last) = stem.rsplit('.').next() {
            if !last.is_empty() && last != stem {
                index
                    .by_stem
                    .entry(last.to_string())
                    .or_insert_with(|| entry.icon.clone());
            }
        }
    }
    if let Some(wm) = entry.wm_class {
        index
            .by_stem
            .entry(wm.to_ascii_lowercase())
            .or_insert_with(|| entry.icon.clone());
    }
}

fn parse_desktop_icon_entry(content: &str) -> Option<ParsedDesktopIconEntry> {
    let mut in_entry = false;
    let mut name: Option<String> = None;
    let mut exec_line: Option<String> = None;
    let mut try_exec: Option<String> = None;
    let mut icon: Option<String> = None;
    let mut wm_class: Option<String> = None;
    let mut no_display = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_entry = trimmed == "[Desktop Entry]";
            continue;
        }
        if !in_entry || trimmed.starts_with('#') {
            continue;
        }
        if name.is_none() {
            if let Some(v) = trimmed.strip_prefix("Name=") {
                name = Some(v.trim().to_string());
            }
        }
        if exec_line.is_none() {
            if let Some(v) = trimmed.strip_prefix("Exec=") {
                exec_line = Some(v.trim().to_string());
            }
        }
        if try_exec.is_none() {
            if let Some(v) = trimmed.strip_prefix("TryExec=") {
                try_exec = Some(v.trim().to_string());
            }
        }
        if icon.is_none() {
            if let Some(v) = trimmed.strip_prefix("Icon=") {
                let v = v.trim();
                if !v.is_empty() {
                    icon = Some(v.to_string());
                }
            }
        }
        if wm_class.is_none() {
            if let Some(v) = trimmed.strip_prefix("StartupWMClass=") {
                let v = v.trim();
                if !v.is_empty() {
                    wm_class = Some(v.to_string());
                }
            }
        }
        if let Some(v) = trimmed.strip_prefix("NoDisplay=") {
            no_display = v.trim().eq_ignore_ascii_case("true");
        }
    }

    let icon = icon?;
    let mut exec_path = None;
    let mut exec_names = Vec::new();

    if let Some(ref exec) = exec_line {
        let (path_opt, names) = parse_exec_tokens(exec);
        exec_path = path_opt;
        exec_names.extend(names);
    }

    if let Some(ref te) = try_exec {
        let cleaned = te.trim_matches('"').trim_matches('\'');
        if exec_path.is_none() && cleaned.starts_with('/') {
            exec_path = Some(cleaned.to_string());
        }
        if let Some(fname) = Path::new(cleaned).file_name() {
            let lower = fname.to_string_lossy().to_ascii_lowercase();
            if !lower.is_empty() && !exec_names.contains(&lower) {
                exec_names.push(lower);
            }
        }
    }

    Some(ParsedDesktopIconEntry {
        name,
        exec_path,
        exec_names,
        wm_class,
        icon,
        no_display,
    })
}

fn parse_exec_tokens(exec_line: &str) -> (Option<String>, Vec<String>) {
    let tokens: Vec<&str> = exec_line
        .split_whitespace()
        .map(|t| t.trim_matches('"').trim_matches('\''))
        .collect();

    // Skip leading `env` and `KEY=VALUE` assignments.
    let mut idx = 0;
    while idx < tokens.len() {
        let tok = tokens[idx];
        if tok == "env" || tok.ends_with("/env") || tok.contains('=') {
            idx += 1;
        } else {
            break;
        }
    }

    let Some(&cmd) = tokens.get(idx) else {
        return (None, Vec::new());
    };

    let mut names = Vec::new();
    let cmd_base = Path::new(cmd)
        .file_name()
        .map(|f| f.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();

    // Handle `flatpak run [flags...] <app-id>`
    if cmd_base == "flatpak" && tokens.get(idx + 1) == Some(&"run") {
        for &arg in &tokens[idx + 2..] {
            if !arg.starts_with('-') && !arg.starts_with('%') {
                let lower = arg.to_ascii_lowercase();
                names.push(lower.clone());
                if let Some(last) = lower.rsplit('.').next() {
                    if last != lower {
                        names.push(last.to_string());
                    }
                }
                break;
            }
        }
        return (None, names);
    }

    // Handle `snap run [flags...] <snap-name>`
    if cmd_base == "snap" && tokens.get(idx + 1) == Some(&"run") {
        for &arg in &tokens[idx + 2..] {
            if !arg.starts_with('-') && !arg.starts_with('%') {
                names.push(arg.to_ascii_lowercase());
                break;
            }
        }
        return (None, names);
    }

    let exec_path = if cmd.starts_with('/') {
        Some(cmd.to_string())
    } else {
        None
    };

    if !cmd_base.is_empty() {
        names.push(cmd_base);
    }

    (exec_path, names)
}

fn icon_base_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(home) = std::env::var("HOME") {
        let h = PathBuf::from(&home);
        dirs.push(h.join(".icons"));
        if let Ok(xdg_home) = std::env::var("XDG_DATA_HOME") {
            if !xdg_home.is_empty() {
                dirs.push(PathBuf::from(xdg_home).join("icons"));
            } else {
                dirs.push(h.join(".local/share/icons"));
            }
        } else {
            dirs.push(h.join(".local/share/icons"));
        }
        dirs.push(h.join(".local/share/flatpak/exports/share/icons"));
    }

    dirs.push(PathBuf::from("/var/lib/flatpak/exports/share/icons"));

    if let Ok(xdg_dirs) = std::env::var("XDG_DATA_DIRS") {
        for dir in xdg_dirs.split(':').filter(|s| !s.is_empty()) {
            dirs.push(PathBuf::from(dir).join("icons"));
        }
    } else {
        dirs.push(PathBuf::from("/usr/local/share/icons"));
        dirs.push(PathBuf::from("/usr/share/icons"));
    }

    // Deduplicate while preserving priority order.
    let mut unique = Vec::new();
    for d in dirs {
        if !unique.contains(&d) {
            unique.push(d);
        }
    }
    unique
}

fn detect_icon_theme_chain() -> Vec<String> {
    let mut seeds = Vec::new();

    // 1. KDE Plasma (`~/.config/kdeglobals`)
    if let Some(kde_theme) = read_kde_icon_theme() {
        seeds.push(kde_theme);
    }

    // 2. GTK 3 / GTK 4 settings (`~/.config/gtk-3.0/settings.ini`, `gtk-4.0/settings.ini`)
    if let Some(gtk_theme) = read_gtk_icon_theme() {
        if !seeds.contains(&gtk_theme) {
            seeds.push(gtk_theme);
        }
    }

    let base_dirs = ICON_BASE_DIRS.get_or_init(icon_base_dirs);
    let mut chain = expand_theme_inheritance(&seeds, base_dirs);

    // Ensure common desktop fallback themes and `hicolor` are always at the end.
    for fallback in ["breeze", "Adwaita", "Yaru", "Papirus", "hicolor"] {
        if !chain.iter().any(|t| t == fallback) {
            chain.push(fallback.to_string());
        }
    }

    chain
}

fn read_kde_icon_theme() -> Option<String> {
    let config_home = std::env::var("XDG_CONFIG_HOME")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var("HOME").ok().map(|h| PathBuf::from(h).join(".config")))?;
    let content = fs::read_to_string(config_home.join("kdeglobals")).ok()?;
    parse_ini_key(&content, "[Icons]", "Theme")
}

fn read_gtk_icon_theme() -> Option<String> {
    let config_home = std::env::var("XDG_CONFIG_HOME")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var("HOME").ok().map(|h| PathBuf::from(h).join(".config")))?;
    for rel in ["gtk-4.0/settings.ini", "gtk-3.0/settings.ini"] {
        if let Ok(content) = fs::read_to_string(config_home.join(rel)) {
            if let Some(theme) = parse_ini_key(&content, "[Settings]", "gtk-icon-theme-name") {
                return Some(theme);
            }
        }
    }
    None
}

fn parse_ini_key(content: &str, section: &str, key: &str) -> Option<String> {
    let mut in_section = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_section = trimmed == section;
            continue;
        }
        if !in_section {
            continue;
        }
        if let Some((k, v)) = trimmed.split_once('=') {
            if k.trim() == key {
                let val = v.trim();
                if !val.is_empty() {
                    return Some(val.to_string());
                }
            }
        }
    }
    None
}

fn expand_theme_inheritance(seeds: &[String], base_dirs: &[PathBuf]) -> Vec<String> {
    let mut result = Vec::new();
    let mut visited = HashSet::new();
    let mut queue: VecDeque<String> = seeds.iter().cloned().collect();

    while let Some(theme) = queue.pop_front() {
        if !visited.insert(theme.clone()) {
            continue;
        }
        result.push(theme.clone());

        for base in base_dirs {
            let index_path = base.join(&theme).join("index.theme");
            if let Ok(content) = fs::read_to_string(&index_path) {
                if let Some(inherits) = parse_ini_key(&content, "[Icon Theme]", "Inherits") {
                    for parent in inherits.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
                        if !visited.contains(parent) {
                            queue.push_back(parent.to_string());
                        }
                    }
                }
                break;
            }
        }
    }

    result
}

fn lookup_icon_in_themes(
    icon_name: &str,
    themes: &[String],
    base_dirs: &[PathBuf],
) -> Option<PathBuf> {
    // Direct absolute file path in `.desktop` `Icon=`
    let as_path = Path::new(icon_name);
    if as_path.is_absolute() {
        if as_path.is_file() && is_supported_icon_file(as_path) {
            return Some(as_path.to_path_buf());
        }
        return None;
    }

    // Strip any accidental extension when searching themes (Freedesktop spec allows e.g. `foo.png`).
    let stem = icon_name
        .strip_suffix(".png")
        .or_else(|| icon_name.strip_suffix(".svg"))
        .or_else(|| icon_name.strip_suffix(".xpm"))
        .unwrap_or(icon_name);

    for theme in themes {
        for base in base_dirs {
            let theme_dir = base.join(theme);
            if !theme_dir.is_dir() {
                continue;
            }
            for sub in SIZE_FIRST_DIRS.iter().chain(CONTEXT_FIRST_DIRS.iter()) {
                let dir = theme_dir.join(sub);
                if !dir.is_dir() {
                    continue;
                }
                for ext in ICON_EXTENSIONS {
                    let candidate = dir.join(format!("{stem}.{ext}"));
                    if candidate.is_file() {
                        return Some(candidate);
                    }
                }
            }
        }
    }

    // Freedesktop fallback: `/usr/share/pixmaps`
    let pixmaps = Path::new("/usr/share/pixmaps");
    if pixmaps.is_dir() {
        for ext in ICON_EXTENSIONS {
            let candidate = pixmaps.join(format!("{stem}.{ext}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }

    None
}

fn is_supported_icon_file(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|ext| {
            let ext = ext.to_ascii_lowercase();
            matches!(ext.as_str(), "png" | "svg" | "jpg" | "jpeg" | "webp" | "ico")
        })
        .unwrap_or(false)
}

fn find_steam_library_cache_icon(app_id: u32) -> Option<PathBuf> {
    let home = std::env::var("HOME").ok()?;
    let h = PathBuf::from(home);
    for rel in [
        ".local/share/Steam/appcache/librarycache",
        ".steam/steam/appcache/librarycache",
        ".var/app/com.valvesoftware.Steam/.local/share/Steam/appcache/librarycache",
        "snap/steam/common/.local/share/Steam/appcache/librarycache",
    ] {
        let cache_dir = h.join(rel);
        if !cache_dir.is_dir() {
            continue;
        }
        // Classic Steam layout: `<appid>_icon.jpg`
        let classic = cache_dir.join(format!("{app_id}_icon.jpg"));
        if classic.is_file() {
            return Some(classic);
        }
        // Newer Steam layout: `<appid>/<hash>.jpg` (prefer small square icon or logo if present)
        let app_dir = cache_dir.join(app_id.to_string());
        if app_dir.is_dir() {
            if let Ok(entries) = fs::read_dir(&app_dir) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    let name = p
                        .file_name()
                        .map(|n| n.to_string_lossy().to_ascii_lowercase())
                        .unwrap_or_default();
                    if name.ends_with(".jpg")
                        && !name.contains("library_hero")
                        && !name.contains("library_600x900")
                        && !name.contains("header")
                        && !name.contains("logo")
                    {
                        return Some(p);
                    }
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_desktop_entry_icon_and_flatpak_exec() {
        let content = r#"
[Desktop Entry]
Type=Application
Name=Discord
Exec=/usr/bin/flatpak run --branch=stable com.discordapp.Discord %U
Icon=com.discordapp.Discord
StartupWMClass=discord
"#;
        let parsed = parse_desktop_icon_entry(content).expect("parsed");
        assert_eq!(parsed.icon, "com.discordapp.Discord");
        assert_eq!(parsed.name.as_deref(), Some("Discord"));
        assert!(parsed.exec_names.contains(&"com.discordapp.discord".to_string()));
        assert!(parsed.exec_names.contains(&"discord".to_string()));
        assert_eq!(parsed.wm_class.as_deref(), Some("discord"));
    }

    #[test]
    fn parses_ini_keys_for_kde_and_gtk() {
        let kde = "[General]\nName=Foo\n\n[Icons]\nTheme=breeze-dark\n";
        assert_eq!(
            parse_ini_key(kde, "[Icons]", "Theme").as_deref(),
            Some("breeze-dark")
        );

        let gtk = "[Settings]\ngtk-icon-theme-name=Adwaita\n";
        assert_eq!(
            parse_ini_key(gtk, "[Settings]", "gtk-icon-theme-name").as_deref(),
            Some("Adwaita")
        );
    }

    #[test]
    fn resolves_breeze_and_hicolor_icons_from_temp_tree() {
        let root = std::env::temp_dir().join(format!("curb-xdg-icon-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);

        let apps_dir = root.join("applications");
        let icons_dir = root.join("icons");
        let breeze_apps = icons_dir.join("breeze/apps/48");
        let hicolor_apps = icons_dir.join("hicolor/48x48/apps");
        fs::create_dir_all(&apps_dir).unwrap();
        fs::create_dir_all(&breeze_apps).unwrap();
        fs::create_dir_all(&hicolor_apps).unwrap();

        fs::write(
            apps_dir.join("org.kde.konsole.desktop"),
            "[Desktop Entry]\nName=Konsole\nExec=/usr/bin/konsole\nIcon=utilities-terminal\n",
        )
        .unwrap();
        fs::write(breeze_apps.join("utilities-terminal.svg"), "<svg/>").unwrap();
        fs::write(hicolor_apps.join("steam_icon_730.png"), b"\x89PNG").unwrap();

        let index = build_desktop_icon_index_from_dirs(&[apps_dir]);
        let themes = vec!["breeze".to_string(), "hicolor".to_string()];
        let base_dirs = vec![icons_dir];

        // Match via `.desktop` Exec path -> KDE Breeze `apps/48/*.svg`
        let req = AppIconRequest {
            exe_path: Some(Path::new("/usr/bin/konsole")),
            exe_name: Some("konsole"),
            app_name: Some("Konsole"),
            steam_app_id: None,
        };
        let cands = collect_icon_candidates(&req, &index);
        assert_eq!(cands.first().map(String::as_str), Some("utilities-terminal"));
        let found = cands
            .iter()
            .find_map(|c| lookup_icon_in_themes(c, &themes, &base_dirs))
            .expect("should find breeze svg");
        assert_eq!(found, breeze_apps.join("utilities-terminal.svg"));

        // Match Steam game via `steam_icon_<appid>` in hicolor
        let steam_req = AppIconRequest {
            exe_path: None,
            exe_name: Some("cs2"),
            app_name: Some("Counter-Strike 2"),
            steam_app_id: Some(730),
        };
        let steam_cands = collect_icon_candidates(&steam_req, &index);
        let found_steam = steam_cands
            .iter()
            .find_map(|c| lookup_icon_in_themes(c, &themes, &base_dirs))
            .expect("should find steam icon");
        assert_eq!(found_steam, hicolor_apps.join("steam_icon_730.png"));

        let _ = fs::remove_dir_all(&root);
    }
}
