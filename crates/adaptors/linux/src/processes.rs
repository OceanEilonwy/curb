use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::process::Command;

use curb_core::adaptors::ProcessDiscoverer;
use curb_core::ipc::{BlockedEvent, RunningAppInfo};
use curb_core::verify::peek_binary;

const SYSTEM_EXCLUDED: &[&str] = &[
    // Init & core system daemons (systemd & Void runit)
    "init",
    "systemd",
    "systemd-journald",
    "systemd-udevd",
    "systemd-logind",
    "systemd-resolved",
    "systemd-timesyncd",
    "systemd-oomd",
    "systemd-networkd",
    "runit",
    "runsvdir",
    "runsv",
    "svlogd",
    "udevd",
    "elogind",
    "seatd",
    "dhcpcd",
    "connmand",
    "socklog",
    "nanoklogd",
    "snooze",
    "chronyd",
    "dbus-daemon",
    "dbus-broker",
    "dbus-broker-launch",
    "polkitd",
    "udisksd",
    "upowerd",
    "accounts-daemon",
    "rtkit-daemon",
    "avahi-daemon",
    "cupsd",
    "cups-browsed",
    "bluetoothd",
    "wpa_supplicant",
    "networkmanager",
    "modemmanager",
    "cron",
    "crond",
    "rsyslogd",
    "agetty",
    "login",
    // Display managers & servers
    "gdm",
    "gdm3",
    "gdm-session-worker",
    "sddm",
    "lightdm",
    "ly",
    "greetd",
    "xorg",
    "xwayland",
    // GNOME
    "gnome-shell",
    "mutter",
    // KDE Plasma 5 & 6
    "kwin_wayland",
    "kwin_x11",
    "plasmashell",
    "kded5",
    "kded6",
    "ksmserver",
    "kactivitymanagerd",
    "kglobalacceld",
    "kwalletd5",
    "kwalletd6",
    "kscreenlocker_greet",
    "polkit-kde-authentication-agent-1",
    // XFCE
    "xfwm4",
    "xfdesktop",
    "xfce4-panel",
    "xfce4-session",
    "xfsettingsd",
    "xfconfd",
    "xfce4-notifyd",
    "xfce4-power-manager",
    "xfce-polkit",
    // Sway, Mango (MangoWC), dwl & wlroots compositors/plumbing
    "sway",
    "swaybg",
    "swaybar",
    "swayidle",
    "swaylock",
    "mango",
    "dwl",
    "hyprland",
    "waybar",
    "mako",
    "dunst",
    "fnott",
    "swww-daemon",
    "wbg",
    "polkit-gnome-authentication-agent-1",
    "lxpolkit",
    "mate-polkit",
    "hyprpolkitagent",
    // Audio, accessibility, portals & Curb itself
    "pipewire",
    "pipewire-pulse",
    "wireplumber",
    "pulseaudio",
    "at-spi-bus-launcher",
    "at-spi2-registryd",
    "xdg-desktop-portal",
    "xdg-desktop-portal-gtk",
    "xdg-desktop-portal-gnome",
    "xdg-desktop-portal-kde",
    "xdg-desktop-portal-wlr",
    "xdg-document-portal",
    "xdg-permission-store",
    "gvfsd",
    "curb-service",
    "curb-app",
];

/// Linux `/proc`-based `ProcessDiscoverer` with `.desktop` display-name resolution
/// and compositor-aware visible-window detection (Sway IPC + Wayland/X11 `/proc` fallback).
#[derive(Debug, Default, Clone, Copy)]
pub struct LinuxProcessDiscoverer;

impl ProcessDiscoverer for LinuxProcessDiscoverer {
    fn visible_window_pids(&self) -> Vec<u32> {
        let mut pids: Vec<u32> = collect_visible_pids().into_iter().collect();
        pids.sort_unstable();
        pids
    }

    fn collect_running_apps(
        &self,
        recent_blocked: &[BlockedEvent],
        caller_visible_pids: Option<&[u32]>,
    ) -> Vec<RunningAppInfo> {
        let visible_pids: HashSet<u32> = match caller_visible_pids {
            Some(pids) if !pids.is_empty() => pids.iter().copied().collect(),
            _ => collect_visible_pids(),
        };
        let desktop_names = curb_xdg::load_desktop_names();

        let mut grouped: HashMap<String, (u32, bool)> = HashMap::new();
        let Ok(entries) = fs::read_dir("/proc") else {
            return Vec::new();
        };

        for entry in entries.flatten() {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            if pid <= 2 {
                continue;
            }
            let Ok(exe_path) = fs::read_link(format!("/proc/{pid}/exe")) else {
                continue;
            };
            let full_path = exe_path.to_string_lossy().to_string();
            if full_path.ends_with(" (deleted)") {
                continue;
            }
            let exe_lower = exe_path
                .file_name()
                .map(|f| f.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default();

            if exe_lower.is_empty() || SYSTEM_EXCLUDED.contains(&exe_lower.as_str()) {
                continue;
            }

            let is_fg = visible_pids.contains(&pid);
            let slot = grouped.entry(full_path).or_insert((0, false));
            slot.0 += 1;
            slot.1 = slot.1 || is_fg;
        }

        let mut apps = Vec::new();
        for (path_str, (count, has_window)) in grouped {
            let path = Path::new(&path_str);
            let Ok(identity) = peek_binary(path) else {
                continue;
            };
            let exe_lower = identity.filename.to_ascii_lowercase();
            let display_name = desktop_names
                .get(&exe_lower)
                .cloned()
                .unwrap_or_else(|| identity.filename.clone());

            let blocked_match = recent_blocked
                .iter()
                .find(|b| b.exe.eq_ignore_ascii_case(&identity.filename));

            apps.push(RunningAppInfo {
                key: format!("run-{}", identity.path),
                name: display_name,
                exe: identity.filename,
                path: identity.path,
                process_count: count,
                background: !has_window,
                tried_connect: blocked_match.is_some(),
                tried_host: blocked_match.map(|b| b.destination.clone()),
                signed: false,
                signer: None,
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

fn collect_visible_pids() -> HashSet<u32> {
    if let Some(sway_pids) = collect_sway_window_pids() {
        if !sway_pids.is_empty() {
            return sway_pids;
        }
    }
    collect_gui_pids()
}

/// Queries Sway's IPC tree (`swaymsg -t get_tree`) when `SWAYSOCK` is present to get
/// exact PIDs of processes that own a mapped window.
fn collect_sway_window_pids() -> Option<HashSet<u32>> {
    let sock = std::env::var("SWAYSOCK").ok()?;
    if sock.is_empty() {
        return None;
    }
    let out = Command::new("swaymsg")
        .args(["-t", "get_tree"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let json = String::from_utf8(out.stdout).ok()?;
    Some(parse_sway_tree_pids(&json))
}

pub fn parse_sway_tree_pids(json: &str) -> HashSet<u32> {
    fn walk(val: &serde_json::Value, out: &mut HashSet<u32>) {
        if let Some(obj) = val.as_object() {
            if let Some(pid) = obj.get("pid").and_then(|v| v.as_u64()) {
                if pid > 0 && pid <= u32::MAX as u64 {
                    out.insert(pid as u32);
                }
            }
            for key in ["nodes", "floating_nodes"] {
                if let Some(arr) = obj.get(key).and_then(|v| v.as_array()) {
                    for child in arr {
                        walk(child, out);
                    }
                }
            }
        }
    }

    let mut pids = HashSet::new();
    if let Ok(root) = serde_json::from_str::<serde_json::Value>(json) {
        walk(&root, &mut pids);
    }
    pids
}

fn collect_gui_pids() -> HashSet<u32> {
    let mut pids = HashSet::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return pids;
    };
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        if let Ok(bytes) = fs::read(format!("/proc/{pid}/environ")) {
            if bytes
                .split(|&b| b == 0)
                .any(|var| var.starts_with(b"DISPLAY=") || var.starts_with(b"WAYLAND_DISPLAY="))
            {
                pids.insert(pid);
            }
        }
    }
    pids
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sway_tree_nodes_and_floating_nodes() {
        let sample = r#"{
            "type": "root",
            "nodes": [
                {
                    "type": "output",
                    "nodes": [
                        { "type": "con", "pid": 1234, "nodes": [] }
                    ],
                    "floating_nodes": [
                        { "type": "floating_con", "pid": 5678, "nodes": [] }
                    ]
                }
            ]
        }"#;
        let pids = parse_sway_tree_pids(sample);
        assert!(pids.contains(&1234));
        assert!(pids.contains(&5678));
        assert_eq!(pids.len(), 2);
    }

    #[test]
    fn excludes_void_and_target_compositor_daemons() {
        for name in [
            "runit",
            "runsv",
            "xfwm4",
            "xfce4-panel",
            "sway",
            "mango",
            "dwl",
            "waybar",
            "xdg-desktop-portal-wlr",
            "kwin_wayland",
            "plasmashell",
        ] {
            assert!(
                SYSTEM_EXCLUDED.contains(&name),
                "expected {name} in SYSTEM_EXCLUDED"
            );
        }
    }
}
