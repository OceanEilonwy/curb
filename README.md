<div align="center">

# Curb

**Block everything. Allow only what matters.**

A lightweight, default-deny Windows internet limiter designed for setups where a trusted admin (a friend, partner, or parent) controls what can go online.

[![Latest Release](https://img.shields.io/github/v/release/OceanEilonwy/curb?style=flat-square&color=4e5be6&label=Download)](https://github.com/OceanEilonwy/curb/releases/latest)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-28b463?style=flat-square)](https://github.com/OceanEilonwy/curb/releases/latest)
[![License](https://img.shields.io/github/license/OceanEilonwy/curb?style=flat-square)](LICENSE)

<h3>
  <a href="https://github.com/OceanEilonwy/curb/releases/latest">Download Latest Release for Windows &rarr;</a>
</h3>

<br />

<img src="docs/assets/curb-preview.png" alt="Curb Allowed Apps and Running Apps Picker" width="840" />

</div>

---

## Why Curb?

Most internet blockers rely on browser extensions or domain blocklists that are trivial to bypass and constantly break games or desktop apps. **Curb flips the model:**

- **Default-deny at the OS firewall (WFP):** Blocks all IPv4 & IPv6 traffic across every network adapter—no kernel driver required.
- **Built for non-technical admins:** Pick open apps from a clean **Running Apps** list or auto-discovered **Steam Games**—no hunting through `AppData` folders. Technical knobs (`TCP/UDP`, DNS whitelists, hashes, sub-process scope) stay neatly tucked inside **Advanced**.
- **Survives game & app updates:** Automatically verifies Authenticode signatures so signed apps keep working after patches; unsigned binaries lock cleanly by SHA-256 hash.
- **Modular Steam preset:** Keeps downloads and multiplayer working reliably while locking Steam's built-in browser (`steamwebhelper.exe`) to a strict DNS whitelist with toggles for **Store**, **Community**, and **Friends**.
- **Separate Curb password:** Protected with Argon2id so a friend or accountability partner can hold the password without needing your Windows Administrator password.
- **Quiet in the taskbar:** Runs as a tiny `LocalSystem` service; the tray window destroys its WebView on close to stay near zero RAM.

---

## Quick Setup (Windows)

1. **[Download the latest release](https://github.com/OceanEilonwy/curb/releases/latest)** (`curb-windows-x64-setup.exe`) and run it—**no Windows Administrator account needed to install**.
2. Launch **Curb** and pick your protection mode on first run:
   - **Full Protection (Recommended):** One-time Windows Admin prompt installs the locked system firewall service (`CurbService`), blocking every app and game across all adapters.
   - **Standard Mode (No Admin):** Starts immediately in your user account using a local per-user proxy—zero admin needed (voluntary; upgrade to Full Protection anytime in Settings).
3. Set your **Curb password** right inside the app, and toggle on **Steam** or any apps/games you want online.

> **Admin recovery:** Any Windows Administrator can run `curb-cli emergency-disable` or `curb-cli set-password` from an elevated prompt at any time.

---

## Building from Source

Built with **Rust**, **Tauri v2**, **SolidJS 2**, and **TypeScript**. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the technical deep dive.

```bash
# Run core & service unit tests
cargo test --workspace

# Build the SolidJS 2 UI
cd apps/curb-app
pnpm install && pnpm build

# Run Tauri desktop dev mode (Windows)
pnpm tauri dev
```

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE).
