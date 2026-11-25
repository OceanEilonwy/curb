use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub mod icons;

use curb_core::adaptors::{AppIcon, AppIconRequest, DesktopIntegration};
use curb_core::store::LINUX_SYSTEM_DATA_DIR;

/// Detected Linux desktop environment or Wayland compositor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesktopEnvironment {
    Kde,
    Gnome,
    Xfce,
    Sway,
    Mango,
    Dwl,
    Other,
}

/// Active display server protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayServer {
    Wayland,
    X11,
    Unknown,
}

/// Snapshot of the active Linux desktop session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DesktopSession {
    pub desktop: DesktopEnvironment,
    pub display_server: DisplayServer,
}

impl DesktopSession {
    /// Detects the active desktop environment and display server from process environment variables.
    pub fn detect() -> Self {
        Self::from_env_lookup(|k| std::env::var(k).ok())
    }

    pub fn from_env_lookup<F>(get: F) -> Self
    where
        F: Fn(&str) -> Option<String>,
    {
        let wayland = get("WAYLAND_DISPLAY")
            .map(|v| !v.is_empty())
            .unwrap_or(false);
        let x11 = get("DISPLAY").map(|v| !v.is_empty()).unwrap_or(false);
        let session_type = get("XDG_SESSION_TYPE")
            .unwrap_or_default()
            .to_ascii_lowercase();

        let display_server = if wayland || session_type == "wayland" {
            DisplayServer::Wayland
        } else if x11 || session_type == "x11" {
            DisplayServer::X11
        } else {
            DisplayServer::Unknown
        };

        let combined = [
            get("XDG_CURRENT_DESKTOP").unwrap_or_default(),
            get("XDG_SESSION_DESKTOP").unwrap_or_default(),
            get("DESKTOP_SESSION").unwrap_or_default(),
        ]
        .join(":")
        .to_ascii_lowercase();

        let desktop = if get("SWAYSOCK").map(|v| !v.is_empty()).unwrap_or(false)
            || has_token(&combined, "sway")
        {
            DesktopEnvironment::Sway
        } else if has_token(&combined, "mango") || has_token(&combined, "mangowc") {
            DesktopEnvironment::Mango
        } else if has_token(&combined, "dwl") {
            DesktopEnvironment::Dwl
        } else if has_token(&combined, "kde") || has_token(&combined, "plasma") {
            DesktopEnvironment::Kde
        } else if has_token(&combined, "xfce") {
            DesktopEnvironment::Xfce
        } else if has_token(&combined, "gnome")
            || has_token(&combined, "ubuntu")
            || has_token(&combined, "cinnamon")
            || has_token(&combined, "budgie")
            || has_token(&combined, "pop")
        {
            DesktopEnvironment::Gnome
        } else {
            DesktopEnvironment::Other
        };

        Self {
            desktop,
            display_server,
        }
    }

    pub fn is_wayland(&self) -> bool {
        self.display_server == DisplayServer::Wayland
    }

    /// Returns `true` for minimal tiling compositors that typically do not run an
    /// XDG autostart daemon, Polkit agent, or system tray unless configured by the user.
    pub fn is_minimal_wlroots_compositor(&self) -> bool {
        matches!(
            self.desktop,
            DesktopEnvironment::Sway | DesktopEnvironment::Mango | DesktopEnvironment::Dwl
        )
    }
}

fn has_token(colon_separated: &str, needle: &str) -> bool {
    colon_separated
        .split([':', ';', ' ', '/'])
        .any(|tok| tok == needle)
}

/// Returns an optional compositor config snippet for compositors that do not run XDG autostart.
pub fn autostart_hint_for_session(session: &DesktopSession) -> Option<&'static str> {
    match session.desktop {
        DesktopEnvironment::Sway => Some(
            "Add to ~/.config/sway/config:\n  exec curb-app\n  for_window [app_id=\"curb-app\"] floating enable",
        ),
        DesktopEnvironment::Mango => Some(
            "Add to ~/.config/mango/config.conf:\n  exec-once=curb-app\n  windowrule=isfloating:1,appid:curb-app",
        ),
        DesktopEnvironment::Dwl => Some(
            "Start Curb from your dwl startup script (`dwl -s`):\n  curb-app --no-tray &",
        ),
        _ => None,
    }
}

/// Checks whether an active `org.kde.StatusNotifierWatcher` (system tray host) is registered
/// on the user's session D-Bus. Returns `false` on compositors without a tray bar (e.g. dwl,
/// Mango, or minimal Sway) so `curb-app` can quit cleanly on window close instead of hiding
/// to an unreachable tray.
pub fn has_status_notifier_watcher() -> bool {
    if let Ok(out) = Command::new("dbus-send")
        .args([
            "--session",
            "--print-reply",
            "--dest=org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus.NameHasOwner",
            "string:org.kde.StatusNotifierWatcher",
        ])
        .output()
    {
        if out.status.success() {
            return String::from_utf8_lossy(&out.stdout).contains("boolean true");
        }
    }

    if let Ok(out) = Command::new("busctl")
        .args([
            "--user",
            "call",
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "NameHasOwner",
            "s",
            "org.kde.StatusNotifierWatcher",
        ])
        .output()
    {
        if out.status.success() {
            return String::from_utf8_lossy(&out.stdout).contains("true");
        }
    }

    // If neither D-Bus inspection CLI is installed, assume full DEs (KDE, XFCE, GNOME)
    // provide a tray while minimal wlroots compositors (Sway, Mango, dwl) may not.
    let session = DesktopSession::detect();
    !session.is_minimal_wlroots_compositor()
}

const POLKIT_AGENT_BINARIES: &[&str] = &[
    "polkit-kde-authentication-agent-1",
    "polkit-gnome-authentication-agent-1",
    "xfce-polkit",
    "lxpolkit",
    "lxqt-policykit-agent",
    "mate-polkit",
    "gnome-shell",
    "hyprpolkitagent",
    "soteria",
    "polkit-dumb-agent",
];

/// Returns `true` if a known graphical Polkit authentication agent process is currently running.
pub fn has_polkit_agent() -> bool {
    let Ok(entries) = fs::read_dir("/proc") else {
        return false;
    };
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        if let Ok(exe) = fs::read_link(format!("/proc/{pid}/exe")) {
            if let Some(name) = exe.file_name().and_then(|f| f.to_str()) {
                let lower = name.to_ascii_lowercase();
                if POLKIT_AGENT_BINARIES.contains(&lower.as_str()) {
                    return true;
                }
            }
        }
    }
    false
}

/// Linux XDG / Polkit / KDE / XFCE / GNOME / wlroots desktop integration adaptor.
#[derive(Debug, Default, Clone, Copy)]
pub struct XdgDesktopIntegration;

impl DesktopIntegration for XdgDesktopIntegration {
    fn launch_elevated_install(&self, migrate_from: &Path) -> Result<(), String> {
        let (cli_path, svc_path) = locate_linux_binaries()?;
        run_pkexec(
            &cli_path,
            &[
                "install",
                "--service-bin",
                &svc_path.to_string_lossy(),
                "--migrate-from",
                &migrate_from.to_string_lossy(),
            ],
        )
    }

    fn launch_elevated_uninstall(&self) -> Result<(), String> {
        let (cli_path, _) = locate_linux_binaries()?;
        run_pkexec(&cli_path, &["uninstall"])
    }

    fn ensure_tray_autostart(&self) {
        let Ok(exe) = std::env::current_exe() else {
            return;
        };
        let Some(cfg) = xdg_config_home() else {
            return;
        };
        let autostart_dir = cfg.join("autostart");
        if fs::create_dir_all(&autostart_dir).is_err() {
            return;
        }
        let desktop_entry = format!(
            "[Desktop Entry]\n\
             Type=Application\n\
             Name=Curb\n\
             Comment=Default-deny application internet limiter\n\
             Exec=\"{}\"\n\
             Icon=curb\n\
             Terminal=false\n\
             Categories=Network;Security;\n\
             X-GNOME-Autostart-enabled=true\n",
            exe.display()
        );
        let _ = fs::write(autostart_dir.join("curb.desktop"), desktop_entry);
    }

    fn set_user_proxy(&self, enable: bool, port: u16) {
        let port_str = port.to_string();

        // 1. GNOME / Cinnamon / Budgie / XFCE GTK & Chromium apps / wlroots GTK apps
        if enable {
            let _ = Command::new("gsettings")
                .args(["set", "org.gnome.system.proxy", "mode", "'manual'"])
                .status();
            let _ = Command::new("gsettings")
                .args(["set", "org.gnome.system.proxy.http", "host", "'127.0.0.1'"])
                .status();
            let _ = Command::new("gsettings")
                .args(["set", "org.gnome.system.proxy.http", "port", &port_str])
                .status();
            let _ = Command::new("gsettings")
                .args(["set", "org.gnome.system.proxy.https", "host", "'127.0.0.1'"])
                .status();
            let _ = Command::new("gsettings")
                .args(["set", "org.gnome.system.proxy.https", "port", &port_str])
                .status();
        } else {
            let _ = Command::new("gsettings")
                .args(["set", "org.gnome.system.proxy", "mode", "'none'"])
                .status();
        }

        // 2. KDE Plasma 5 / 6 (`kioslaverc` + live KIO D-Bus reload signal)
        let kwrite = if Command::new("kwriteconfig6").arg("--version").output().is_ok() {
            Some("kwriteconfig6")
        } else if Command::new("kwriteconfig5").arg("--version").output().is_ok() {
            Some("kwriteconfig5")
        } else {
            None
        };
        if let Some(tool) = kwrite {
            let proxy_url = format!("http://127.0.0.1:{port}");
            if enable {
                let _ = Command::new(tool)
                    .args([
                        "--file",
                        "kioslaverc",
                        "--group",
                        "Proxy Settings",
                        "--key",
                        "ProxyType",
                        "1",
                    ])
                    .status();
                let _ = Command::new(tool)
                    .args([
                        "--file",
                        "kioslaverc",
                        "--group",
                        "Proxy Settings",
                        "--key",
                        "httpProxy",
                        &proxy_url,
                    ])
                    .status();
                let _ = Command::new(tool)
                    .args([
                        "--file",
                        "kioslaverc",
                        "--group",
                        "Proxy Settings",
                        "--key",
                        "httpsProxy",
                        &proxy_url,
                    ])
                    .status();
            } else {
                let _ = Command::new(tool)
                    .args([
                        "--file",
                        "kioslaverc",
                        "--group",
                        "Proxy Settings",
                        "--key",
                        "ProxyType",
                        "0",
                    ])
                    .status();
            }
            notify_kde_kio_proxy_reload();
        }

        // 3. Managed `environment.d` drop-in for XFCE / Sway / Mango / dwl / CLI apps
        sync_environment_d_proxy(enable, port);
    }

    fn system_data_dir(&self) -> PathBuf {
        PathBuf::from(LINUX_SYSTEM_DATA_DIR)
    }

    fn user_data_dir(&self) -> PathBuf {
        if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
            if !xdg.is_empty() {
                return PathBuf::from(xdg).join("curb-user");
            }
        }
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(".local/share/curb-user");
        }
        PathBuf::from("/tmp/curb-user")
    }

    fn exe_path_prompt(&self) -> (&'static str, &'static str) {
        (
            "Enter or paste the full path to an executable binary on this computer.",
            "/usr/bin/example",
        )
    }

    fn resolve_app_icon(&self, req: &AppIconRequest<'_>) -> Option<AppIcon> {
        icons::resolve_app_icon(req)
    }
}

fn xdg_config_home() -> Option<PathBuf> {
    std::env::var("XDG_CONFIG_HOME")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .map(|h| PathBuf::from(h).join(".config"))
        })
}

fn notify_kde_kio_proxy_reload() {
    let _ = Command::new("dbus-send")
        .args([
            "--session",
            "--type=signal",
            "/KIO/Scheduler",
            "org.kde.KIO.Scheduler.reparseSlaveConfiguration",
            "string:",
        ])
        .status();
}

pub fn build_environment_d_proxy_conf(port: u16) -> String {
    format!(
        "# Managed by Curb Standard Mode (removed automatically when disabled)\n\
         http_proxy=http://127.0.0.1:{port}\n\
         https_proxy=http://127.0.0.1:{port}\n\
         HTTP_PROXY=http://127.0.0.1:{port}\n\
         HTTPS_PROXY=http://127.0.0.1:{port}\n\
         no_proxy=localhost,127.0.0.1,::1\n\
         NO_PROXY=localhost,127.0.0.1,::1\n"
    )
}

fn sync_environment_d_proxy(enable: bool, port: u16) {
    let Some(cfg) = xdg_config_home() else {
        return;
    };
    let env_dir = cfg.join("environment.d");
    let env_file = env_dir.join("90-curb-proxy.conf");
    if enable {
        if fs::create_dir_all(&env_dir).is_ok() {
            let _ = fs::write(&env_file, build_environment_d_proxy_conf(port));
        }
    } else if env_file.exists() {
        let _ = fs::remove_file(&env_file);
    }
}

/// Reads `.desktop` files from standard XDG, Flatpak, and Snap application directories
/// to map executable basenames (lowercased) to human-friendly display names.
pub fn load_desktop_names() -> HashMap<String, String> {
    let mut map = HashMap::new();
    let mut dirs = vec![
        PathBuf::from("/usr/share/applications"),
        PathBuf::from("/usr/local/share/applications"),
        PathBuf::from("/var/lib/flatpak/exports/share/applications"),
        PathBuf::from("/var/lib/snapd/desktop/applications"),
    ];
    if let Ok(home) = std::env::var("HOME") {
        dirs.push(PathBuf::from(home).join(".local/share/applications"));
    }

    for dir in dirs {
        let Ok(entries) = fs::read_dir(&dir) else {
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
            if let Some((bin_lower, app_name)) = parse_desktop_entry(&content) {
                map.entry(bin_lower).or_insert(app_name);
            }
        }
    }
    map
}

pub fn parse_desktop_entry(content: &str) -> Option<(String, String)> {
    let mut in_entry = false;
    let mut name: Option<String> = None;
    let mut exec: Option<String> = None;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_entry = trimmed == "[Desktop Entry]";
            continue;
        }
        if !in_entry {
            continue;
        }
        if name.is_none() {
            if let Some(val) = trimmed.strip_prefix("Name=") {
                name = Some(val.trim().to_string());
            }
        }
        if exec.is_none() {
            if let Some(val) = trimmed.strip_prefix("Exec=") {
                exec = Some(val.trim().to_string());
            }
        }
        if name.is_some() && exec.is_some() {
            break;
        }
    }
    let (app_name, exec_line) = (name?, exec?);
    let bin = exec_line
        .split_whitespace()
        .find(|tok| *tok != "env" && !tok.contains('='))
        .map(|tok| tok.trim_matches('"').trim_matches('\''))
        .and_then(|tok| Path::new(tok).file_name())
        .map(|f| f.to_string_lossy().to_ascii_lowercase())?;
    Some((bin, app_name))
}

fn locate_linux_binaries() -> Result<(PathBuf, PathBuf), String> {
    let mut cli_candidates = Vec::new();
    let mut svc_candidates = Vec::new();

    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            cli_candidates.push(dir.join("curb-cli"));
            svc_candidates.push(dir.join("curb-service"));
        }
    }
    for p in ["/usr/bin/curb-cli", "/usr/local/bin/curb-cli"] {
        cli_candidates.push(PathBuf::from(p));
    }
    for p in [
        "/usr/libexec/curb/curb-service",
        "/usr/lib/curb/curb-service",
        "/usr/local/libexec/curb/curb-service",
        "/usr/bin/curb-service",
        "/usr/local/bin/curb-service",
    ] {
        svc_candidates.push(PathBuf::from(p));
    }

    let cli = cli_candidates.into_iter().find(|p| p.exists()).ok_or_else(|| {
        "Could not find curb-cli. Install the full Curb Linux package (.deb, .rpm, Arch/CachyOS PKGBUILD, Void XBPS, or tarball)."
            .to_string()
    })?;
    let svc = svc_candidates.into_iter().find(|p| p.exists()).ok_or_else(|| {
        "Could not find curb-service. Install the full Curb Linux package (.deb, .rpm, Arch/CachyOS PKGBUILD, Void XBPS, or tarball)."
            .to_string()
    })?;

    Ok((cli, svc))
}

fn preferred_cli_elevator() -> &'static str {
    if Path::new("/usr/bin/doas").exists() && !Path::new("/usr/bin/sudo").exists() {
        "doas"
    } else {
        "sudo"
    }
}

fn run_pkexec(cli: &Path, args: &[&str]) -> Result<(), String> {
    let cli_cmd = format!("{} {} {}", preferred_cli_elevator(), cli.display(), args.join(" "));
    let status = Command::new("pkexec")
        .arg(cli)
        .args(args)
        .status()
        .map_err(|e| {
            format!(
                "Could not launch pkexec for administrator elevation ({e}). Run `{cli_cmd}` in a terminal instead."
            )
        })?;
    if status.success() {
        Ok(())
    } else if status.code() == Some(127) && !has_polkit_agent() {
        Err(format!(
            "No graphical Polkit authentication agent is running in this desktop session. Start a Polkit agent or run `{cli_cmd}` in a terminal."
        ))
    } else if status.code() == Some(126) || status.code() == Some(127) {
        Err(format!(
            "Administrator approval was canceled or blocked. You can also run `{cli_cmd}` in a terminal."
        ))
    } else {
        Err(format!("Elevated command exited with status {status}."))
    }
}

/// Information about the desktop user who invoked an elevated command (`sudo`/`doas`/`pkexec`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvokingUser {
    pub username: String,
    pub uid: u32,
    pub home_dir: PathBuf,
}

/// Resolves the invoking desktop user's username, UID, and home directory, even when
/// running as root via `sudo`, `doas`, or `pkexec`.
pub fn resolve_invoking_user() -> Option<InvokingUser> {
    let passwd = fs::read_to_string("/etc/passwd").ok()?;

    for var in ["SUDO_USER", "DOAS_USER"] {
        if let Ok(user) = std::env::var(var) {
            if !user.is_empty() && user != "root" {
                if let Some(found) = parse_passwd_by_username(&passwd, &user) {
                    return Some(found);
                }
            }
        }
    }

    if let Ok(uid_str) = std::env::var("PKEXEC_UID") {
        if let Ok(uid) = uid_str.trim().parse::<u32>() {
            if uid != 0 {
                if let Some(found) = parse_passwd_by_uid(&passwd, uid) {
                    return Some(found);
                }
            }
        }
    }

    if let Ok(user) = std::env::var("USER") {
        if !user.is_empty() {
            if let Some(found) = parse_passwd_by_username(&passwd, &user) {
                return Some(found);
            }
        }
    }

    std::env::var("HOME")
        .ok()
        .filter(|h| !h.is_empty())
        .map(|h| InvokingUser {
            username: std::env::var("USER").unwrap_or_default(),
            uid: 0,
            home_dir: PathBuf::from(h),
        })
}

pub fn parse_passwd_by_username(passwd: &str, target: &str) -> Option<InvokingUser> {
    for line in passwd.lines() {
        let mut fields = line.split(':');
        let name = fields.next()?;
        let _pw = fields.next()?;
        let uid = fields.next()?.parse::<u32>().ok()?;
        let _gid = fields.next()?;
        let _gecos = fields.next()?;
        let home = fields.next()?;
        if name == target && !home.is_empty() {
            return Some(InvokingUser {
                username: name.to_string(),
                uid,
                home_dir: PathBuf::from(home),
            });
        }
    }
    None
}

pub fn parse_passwd_by_uid(passwd: &str, target_uid: u32) -> Option<InvokingUser> {
    for line in passwd.lines() {
        let mut fields = line.split(':');
        let name = fields.next()?;
        let _pw = fields.next()?;
        let uid = fields.next()?.parse::<u32>().ok()?;
        let _gid = fields.next()?;
        let _gecos = fields.next()?;
        let home = fields.next()?;
        if uid == target_uid && !home.is_empty() {
            return Some(InvokingUser {
                username: name.to_string(),
                uid,
                home_dir: PathBuf::from(home),
            });
        }
    }
    None
}

/// Cleans up Curb's per-user desktop configuration (XDG autostart, `environment.d` proxy
/// drop-in, GNOME/GTK `gsettings` proxy, KDE `kioslaverc` proxy, and optionally
/// `~/.local/share/curb-user`) for the invoking desktop user.
pub fn cleanup_invoking_user_desktop_config(remove_user_data: bool) -> Vec<String> {
    let Some(user) = resolve_invoking_user() else {
        return Vec::new();
    };
    let mut cleaned = cleanup_user_files(&user.home_dir, remove_user_data);

    // Clear GNOME/GTK gsettings proxy (running as the invoking user if we are root)
    let dbus_addr = format!("unix:path=/run/user/{}/bus", user.uid);
    let ran_as_user = !user.username.is_empty() && user.uid != 0;
    let gsettings_ok = if ran_as_user {
        Command::new("su")
            .args([
                "-s",
                "/bin/sh",
                &user.username,
                "-c",
                &format!(
                    "DBUS_SESSION_BUS_ADDRESS='{dbus_addr}' gsettings set org.gnome.system.proxy mode 'none'"
                ),
            ])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    } else {
        Command::new("gsettings")
            .args(["set", "org.gnome.system.proxy", "mode", "'none'"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    };
    if gsettings_ok {
        cleaned.push("Reset GNOME/GTK proxy mode (gsettings)".into());
    }

    // Clear KDE Plasma 5/6 kioslaverc proxy directly on the user's config file
    let kioslaverc = user.home_dir.join(".config/kioslaverc");
    if kioslaverc.exists() {
        let kwrite = if Command::new("kwriteconfig6").arg("--version").output().is_ok() {
            Some("kwriteconfig6")
        } else if Command::new("kwriteconfig5").arg("--version").output().is_ok() {
            Some("kwriteconfig5")
        } else {
            None
        };
        if let Some(tool) = kwrite {
            let ok = Command::new(tool)
                .args([
                    "--file",
                    &kioslaverc.to_string_lossy(),
                    "--group",
                    "Proxy Settings",
                    "--key",
                    "ProxyType",
                    "0",
                ])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if ok {
                cleaned.push(format!("Reset KDE proxy in {}", kioslaverc.display()));
                if ran_as_user {
                    let _ = Command::new("su")
                        .args([
                            "-s",
                            "/bin/sh",
                            &user.username,
                            "-c",
                            &format!(
                                "DBUS_SESSION_BUS_ADDRESS='{dbus_addr}' dbus-send --session --type=signal /KIO/Scheduler org.kde.KIO.Scheduler.reparseSlaveConfiguration string:"
                            ),
                        ])
                        .status();
                } else {
                    notify_kde_kio_proxy_reload();
                }
            }
        }
    }

    cleaned
}

/// Removes Curb's managed files under `home_dir` (`autostart/curb.desktop`,
/// `environment.d/90-curb-proxy.conf`, and optionally `.local/share/curb-user`).
pub fn cleanup_user_files(home_dir: &Path, remove_user_data: bool) -> Vec<String> {
    let mut removed = Vec::new();
    for rel in [
        ".config/autostart/curb.desktop",
        ".config/environment.d/90-curb-proxy.conf",
    ] {
        let path = home_dir.join(rel);
        if path.exists() && fs::remove_file(&path).is_ok() {
            removed.push(format!("Removed {}", path.display()));
        }
    }
    if remove_user_data {
        let user_data = home_dir.join(".local/share/curb-user");
        if user_data.exists() && fs::remove_dir_all(&user_data).is_ok() {
            removed.push(format!("Removed {}", user_data.display()));
        }
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_desktop_entry_with_env_prefix() {
        let content = r#"
[Desktop Entry]
Type=Application
Name=Mozilla Firefox
Exec=env MOZ_ENABLE_WAYLAND=1 /usr/lib/firefox/firefox %u
"#;
        let parsed = parse_desktop_entry(content).expect("parsed");
        assert_eq!(parsed.0, "firefox");
        assert_eq!(parsed.1, "Mozilla Firefox");
    }

    #[test]
    fn detects_target_desktops_and_compositors() {
        let make = |pairs: &[(&str, &str)]| {
            let map: HashMap<&str, &str> = pairs.iter().copied().collect();
            DesktopSession::from_env_lookup(|k| map.get(k).map(|v| (*v).to_string()))
        };

        let kde = make(&[
            ("XDG_CURRENT_DESKTOP", "KDE"),
            ("WAYLAND_DISPLAY", "wayland-0"),
        ]);
        assert_eq!(kde.desktop, DesktopEnvironment::Kde);
        assert_eq!(kde.display_server, DisplayServer::Wayland);
        assert!(!kde.is_minimal_wlroots_compositor());

        let xfce = make(&[("XDG_CURRENT_DESKTOP", "XFCE"), ("DISPLAY", ":0")]);
        assert_eq!(xfce.desktop, DesktopEnvironment::Xfce);
        assert_eq!(xfce.display_server, DisplayServer::X11);
        assert!(!xfce.is_minimal_wlroots_compositor());

        let sway = make(&[
            ("SWAYSOCK", "/run/user/1000/sway-ipc.sock"),
            ("WAYLAND_DISPLAY", "wayland-1"),
        ]);
        assert_eq!(sway.desktop, DesktopEnvironment::Sway);
        assert!(sway.is_minimal_wlroots_compositor());
        assert!(autostart_hint_for_session(&sway).is_some());

        let mango = make(&[
            ("XDG_CURRENT_DESKTOP", "mango"),
            ("WAYLAND_DISPLAY", "wayland-0"),
        ]);
        assert_eq!(mango.desktop, DesktopEnvironment::Mango);
        assert!(mango.is_minimal_wlroots_compositor());
        assert!(autostart_hint_for_session(&mango).is_some());

        let dwl = make(&[
            ("XDG_CURRENT_DESKTOP", "dwl"),
            ("WAYLAND_DISPLAY", "wayland-0"),
        ]);
        assert_eq!(dwl.desktop, DesktopEnvironment::Dwl);
        assert!(dwl.is_minimal_wlroots_compositor());
        assert!(autostart_hint_for_session(&dwl).is_some());
    }

    #[test]
    fn formats_environment_d_proxy_conf() {
        let conf = build_environment_d_proxy_conf(31280);
        assert!(conf.contains("http_proxy=http://127.0.0.1:31280"));
        assert!(conf.contains("HTTPS_PROXY=http://127.0.0.1:31280"));
        assert!(conf.contains("no_proxy=localhost,127.0.0.1,::1"));
    }

    #[test]
    fn parses_passwd_entries_by_name_and_uid() {
        let sample = "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000:Alice:/home/alice:/bin/zsh\n";
        let by_name = parse_passwd_by_username(sample, "alice").expect("alice");
        assert_eq!(by_name.uid, 1000);
        assert_eq!(by_name.home_dir, PathBuf::from("/home/alice"));

        let by_uid = parse_passwd_by_uid(sample, 1000).expect("uid 1000");
        assert_eq!(by_uid.username, "alice");
        assert_eq!(by_uid.home_dir, PathBuf::from("/home/alice"));
    }

    #[test]
    fn cleans_up_user_autostart_proxy_and_optional_data() {
        let home = std::env::temp_dir().join(format!("curb_xdg_clean_{}", std::process::id()));
        let _ = fs::remove_dir_all(&home);
        fs::create_dir_all(home.join(".config/autostart")).unwrap();
        fs::create_dir_all(home.join(".config/environment.d")).unwrap();
        fs::create_dir_all(home.join(".local/share/curb-user")).unwrap();

        let autostart = home.join(".config/autostart/curb.desktop");
        let proxy_conf = home.join(".config/environment.d/90-curb-proxy.conf");
        let user_cfg = home.join(".local/share/curb-user/config.json");
        fs::write(&autostart, "[Desktop Entry]\n").unwrap();
        fs::write(&proxy_conf, "http_proxy=http://127.0.0.1:31280\n").unwrap();
        fs::write(&user_cfg, "{}").unwrap();

        // Without purge, autostart and proxy drop-in are removed while curb-user stays
        let cleaned = cleanup_user_files(&home, false);
        assert_eq!(cleaned.len(), 2);
        assert!(!autostart.exists());
        assert!(!proxy_conf.exists());
        assert!(user_cfg.exists());

        // With purge, curb-user data directory is also removed
        let purged = cleanup_user_files(&home, true);
        assert_eq!(purged.len(), 1);
        assert!(!home.join(".local/share/curb-user").exists());

        let _ = fs::remove_dir_all(&home);
    }
}
