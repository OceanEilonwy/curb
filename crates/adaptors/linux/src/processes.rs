use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use curb_core::adaptors::ProcessDiscoverer;
use curb_core::ipc::{BlockedEvent, RunningAppInfo};
use curb_core::verify::peek_binary;

const SYSTEM_EXCLUDED: &[&str] = &[
    "systemd",
    "systemd-journald",
    "systemd-udevd",
    "systemd-logind",
    "systemd-resolved",
    "systemd-timesyncd",
    "systemd-oomd",
    "systemd-networkd",
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
    "gdm",
    "gdm3",
    "gdm-session-worker",
    "sddm",
    "lightdm",
    "xorg",
    "xwayland",
    "gnome-shell",
    "kwin_wayland",
    "kwin_x11",
    "plasmashell",
    "mutter",
    "sway",
    "hyprland",
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
    "xdg-document-portal",
    "xdg-permission-store",
    "gvfsd",
    "init",
    "curb-service",
    "curb-app",
];

/// Linux `/proc`-based `ProcessDiscoverer` with `.desktop` display-name resolution.
#[derive(Debug, Default, Clone, Copy)]
pub struct LinuxProcessDiscoverer;

impl ProcessDiscoverer for LinuxProcessDiscoverer {
    fn visible_window_pids(&self) -> Vec<u32> {
        let mut pids: Vec<u32> = collect_gui_pids().into_iter().collect();
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
            _ => collect_gui_pids(),
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
