# Linux Distributions & Desktop Environments

Curb runs natively on both **`systemd`** and **`runit`** Linux systems using `nftables` + `NFQUEUE` and a pure-Rust software-rendered Slint UI.

---

## Distributions

### CachyOS (and Arch Linux)
- **Install native `.pkg.tar.zst` package from GitHub Releases:**
  ```bash
  sudo pacman -U ./curb-*-x86_64.pkg.tar.zst
  ```
  *(Or build from source with `cd packaging/linux && makepkg -si` to compile with your CachyOS `makepkg.conf` `RUSTFLAGS`.)*
- **UFW / firewalld coexistence:** Curb uses its own isolated `table inet curb` (`output` priority `0`, `nat_output` priority `-100`), which coexists cleanly with CachyOS's default `ufw` setup.
- **Service management:** `sudo curb-cli install` enables `curb.service` via `systemd`.

### Void Linux (`runit`, glibc & musl)
- **Install native `.xbps` package from GitHub Releases:**
  ```bash
  xbps-rindex -a ./curb-*.x86_64.xbps && sudo xbps-install -R . curb
  ```
  *(Or build for musl/custom targets from source via `packaging/linux/void/template` with `xbps-src`, or install via the universal `.tar.gz` + `sudo ./install.sh`.)*
- **Service management:** `sudo curb-cli install` (or `doas curb-cli install`) automatically detects `runit`, writes `/etc/sv/curb`, symlinks `/var/service/curb`, and starts the service via `sv up curb`. Logs are written to `/var/log/curb` when `svlogd` is installed.
- **DNS resolvers:** Curb discovers upstream resolvers from `/run/resolvconf/resolv.conf` (`openresolv`), `/run/NetworkManager/no-stub-resolv.conf`, `/run/NetworkManager/resolv.conf`, `/var/run/connman/resolv.conf`, and `/etc/resolv.conf`.

---

## Desktop Environments & Compositors

### KDE Plasma (5 & 6, Wayland & X11)
- Works out of the box with `StatusNotifierItem` tray, `polkit-kde-agent`, XDG autostart, and live Standard Mode proxy updates (`kwriteconfig6`/`kwriteconfig5` + KIO D-Bus `reparseSlaveConfiguration` signal).
- `curb.desktop` sets `StartupWMClass=curb-app` for taskbar icon matching.

### XFCE
- Works out of the box on X11 with `xfce4-panel` StatusNotifier tray, XDG autostart, and window geometry save/restore.
- Standard Mode proxy updates both `gsettings` (GTK/Chromium/Electron apps) and `~/.config/environment.d/90-curb-proxy.conf`.
- For graphical elevation prompts, ensure `xfce-polkit` or `polkit-gnome` is running (otherwise use `sudo curb-cli install`).

### Sway
- **Exact foreground app detection:** When `SWAYSOCK` is set, Curb queries `swaymsg -t get_tree` to distinguish foreground windows from background processes.
- **Recommended `~/.config/sway/config` snippet:**
  ```sway
  # Optional: start a Polkit agent for one-click Full Protection elevation
  exec /usr/lib/polkit-gnome/polkit-gnome-authentication-agent-1

  # Start Curb and float its window
  exec curb-app
  for_window [app_id="curb-app"] floating enable
  ```
- **Tray & reactivation:** If `waybar` (or `swaybar` with SNI) is running, Curb docks into the tray; if no `StatusNotifierWatcher` is active, closing the window quits `curb-app` cleanly while `curb-service` continues enforcing. Re-running `curb-app` from a keybind/launcher focuses any existing window via `$XDG_RUNTIME_DIR/curb-app.sock`.

### Mango (MangoWC)
- **Recommended `~/.config/mango/config.conf` snippet:**
  ```ini
  exec-once=curb-app
  windowrule=isfloating:1,appid:curb-app
  ```
- Works with or without a tray bar (e.g. `waybar`). Without a tray, closing the window exits `curb-app` cleanly and re-launching `curb-app` from a keybind/launcher reopens it.

### dwl
- Stock `dwl` has no built-in bar, tray, Polkit agent, or XDG autostart:
  - Curb automatically detects the absence of `StatusNotifierWatcher` and runs in window-only mode (or pass `curb-app --no-tray`).
  - Re-launching `curb-app` from your launcher/keybind (`fuzzel`, `bemenu`, `wmenu`) focuses the existing window via `$XDG_RUNTIME_DIR/curb-app.sock`.
  - Enable Full Protection once from a terminal (`sudo curb-cli install` or `doas curb-cli install`), or start a Polkit agent in your `dwl -s` startup script.

---

## Clean Uninstall

Curb uses a single canonical uninstall path on Linux (`curb-cli uninstall`). To stop and unregister the system service (`systemd` or Void `runit`), delete `table inet curb` from `nftables`, reset per-user desktop autostart & proxy config (`~/.config/autostart/curb.desktop`, `~/.config/environment.d/90-curb-proxy.conf`, `gsettings`, KDE `kioslaverc`), purge `/var/lib/curb`, `/var/log/curb`, and `~/.local/share/curb-user`, and remove tarball-installed binaries:

```bash
sudo curb-cli uninstall --purge
```

- Omit `--purge` to keep `/var/lib/curb` and `~/.local/share/curb-user` for future reinstalls.
- All distro package removal hooks (`.deb` `prerm`, `.rpm` `%preun`, Arch/CachyOS `curb.install`, and Void `REMOVE`) delegate directly to `curb-cli uninstall`. If Curb was installed via a package manager, `curb-cli uninstall --purge` leaves package-tracked binaries to the package manager and prints the exact removal command.
