use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub mod icons;

use curb_core::adaptors::{AppIcon, AppIconRequest, DesktopIntegration};
use curb_core::store::LINUX_SYSTEM_DATA_DIR;

/// Linux XDG / Polkit / GNOME / KDE desktop integration adaptor.
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
        let config_dir = std::env::var("XDG_CONFIG_HOME")
            .ok()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var("HOME")
                    .ok()
                    .map(|h| PathBuf::from(h).join(".config"))
            });
        let Some(cfg) = config_dir else {
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
        // GNOME / Cinnamon / Budgie / Pop!_OS / Ubuntu Desktop
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

        // KDE Plasma 5 / 6
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
        }
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
        "Could not find curb-cli. Install the full Curb Linux package (.deb, .rpm, or tarball)."
            .to_string()
    })?;
    let svc = svc_candidates.into_iter().find(|p| p.exists()).ok_or_else(|| {
        "Could not find curb-service. Install the full Curb Linux package (.deb, .rpm, or tarball)."
            .to_string()
    })?;

    Ok((cli, svc))
}

fn run_pkexec(cli: &Path, args: &[&str]) -> Result<(), String> {
    let status = Command::new("pkexec")
        .arg(cli)
        .args(args)
        .status()
        .map_err(|e| {
            format!(
                "Could not launch pkexec for administrator elevation ({e}). Run `sudo {} {}` in a terminal instead.",
                cli.display(),
                args.join(" ")
            )
        })?;
    if status.success() {
        Ok(())
    } else if status.code() == Some(126) || status.code() == Some(127) {
        Err("Administrator approval was canceled or blocked.".into())
    } else {
        Err(format!("Elevated command exited with status {status}."))
    }
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
}
