# Curb Architecture

Curb is a default-deny, application-centric Windows internet limiter designed for setups where the daily user operates a standard (non-administrator) Windows account and a trusted administrator (parent, partner, friend, or self with separate credentials) controls what can connect online.

## Design Goals

1. **Default-deny across all network adapters (IPv4 + IPv6):** Everything is blocked at the Windows Filtering Platform (WFP) layer unless explicitly matched by an active rule or essential OS baseline.
2. **No kernel driver required:** Pure user-mode enforcement via a `LocalSystem` Windows Service combining persistent default-deny WFP filters, ETW process monitoring, Authenticode/SHA-256 verification, NTFS handle locking, and dynamic session-scoped WFP allow filters.
3. **Human-first UI with Advanced escape hatch:** Plain-language controls for non-technical admins (Activity Monitor-style Running Apps picker, Steam library auto-detection, WCAG AA contrast in Dark & Light), with protocols (`TCP`/`UDP`), sub-process policies, DNS whitelists, and baseline settings cleanly tucked behind **Advanced** disclosures.
4. **Flexible administration:** Separate Curb admin password (Argon2id hash stored in admin-only `C:\ProgramData\Curb\auth.json`) so a friend or accountability partner can hold the password without needing the Windows admin password. Elevated Windows administrators always retain recovery via `curb-cli`.

---

## Workspace Layout

```text
curb/
├── crates/
│   ├── curb-core/       # Shared schema, presets, DNS wildcard matcher, Argon2id auth, Steam VDF parser, verification, IPC protocol
│   ├── curb-service/    # LocalSystem Windows Service (WFP, ETW, Adapter DNS manager, local DNS proxy, Named Pipe IPC server)
│   └── curb-cli/        # Elevated admin CLI (install, uninstall, reset-password, emergency-disable, status)
└── apps/
    └── curb-app/        # Unprivileged pure-Rust Slint system tray app (software renderer)
```

---

## Enforcement Architecture

### 1. Windows Filtering Platform (WFP)
- **Persistent Default-Deny Sublayer:** Registered with `FWPM_FILTER_FLAG_PERSISTENT` on `ALE_AUTH_CONNECT_V4/V6` and `ALE_AUTH_RECV_ACCEPT_V4/V6`. Ensures the machine fails closed even before `curb-service` starts or during crashes.
- **Essential Baseline Layer:** Configurable rules for `DHCP`, `Loopback (127.0.0.1 / ::1)`, `NTP` (time sync for TLS), `Windows NCSI` (prevents false "No Internet" flags), and outbound UDP/TCP 53 *strictly* for `curb-service` itself (blocking external DNS/DoT port 53 & 853 for all other processes).
- **Dynamic Session Filters (`FWPM_SESSION_FLAG_DYNAMIC`):** When a running process passes signature or hash verification, `curb-service` inserts a temporary `PERMIT` filter scoped to its NT device path (`ALE_APP_ID`), allowed protocol(s) (`TCP`/`UDP`), and—when a DNS whitelist is configured—only the IPs resolved via Curb's DNS proxy for matching domains. When the process exits (or if the service stops), dynamic filters are removed automatically.

### 2. Process Verification & Anti-Swap Protection
- **ETW Process Watcher:** Subscribes to `Microsoft-Windows-Kernel-Process` start/stop events.
- **Authenticode & Hash Verification:**
  - **Signed apps (`Signature` / signed `SteamGame`):** Verified via `WinVerifyTrust` (valid trust chain) + publisher subject CN + optional PE `ProductName` / `OriginalFilename` constraint (preventing broad signers like `Microsoft Corporation` from over-allowing unrelated apps). Survives app updates.
  - **Unsigned apps (`Hash` / unsigned `SteamGame`):** Verified by exact SHA-256 digest; requires admin re-approval on update.
- **Rename-and-Swap Mitigation:** While an allowed process is running, `curb-service` holds an open file handle to its `.exe` with `FILE_SHARE_READ` only (no `FILE_SHARE_WRITE` or `FILE_SHARE_DELETE`), preventing a standard user from renaming/replacing a running binary or its parent folder in user-writable directories (such as Steam libraries).
- **Sub-Process Inheritance:** Supports `Disabled`, `SameSignerOrDir` (recommended default when enabled), and `AnyExceptRestricted`, always excluding common browsers (`msedge.exe`, `chrome.exe`, `firefox.exe`, etc.) and shells (`powershell.exe`, `cmd.exe`, `curl.exe`, `winget.exe`).

### 3. Per-App DNS Whitelisting
- On activation, `curb-service` snapshots each adapter's original DNS configuration (DHCP vs. static servers) to `C:\ProgramData\Curb\dns_backup.json` and points adapters to `127.0.0.1` / `::1`.
- Watches for newly connected adapters via `NotifyIpInterfaceChange`.
- Runs an async local DNS proxy (`curb-service/src/dns_proxy.rs`) that forwards permitted queries upstream, parses A/AAAA answers, caches `(domain -> [IPs, expires_at])`, and updates the corresponding app's dynamic WFP IP filters.
- Restores original adapter DNS settings when disabled or uninstalled.

### 4. Built-in Steam Preset
- **`steam.exe` & `steamservice.exe` (Valve Corp. signed):** Always allowed on TCP/UDP when the Steam preset is enabled so login, game downloads, cloud saves, and Steam Networking Sockets work reliably (even for direct CM server IPs).
- **`steamwebhelper.exe` (Embedded Chromium):** Strictly locked to Curb's DNS whitelist based on user-friendly toggles:
  - **Store & Library:** `store.steampowered.com`, `checkout.steampowered.com`, `login.steampowered.com`, `api.steampowered.com`, `*.steamstatic.com`, `*.steamcontent.com`
  - **Community & Workshop:** adds `steamcommunity.com`, `*.steamusercontent.com`
  - **Friends & Voice:** adds `*.steam-chat.com`

### 5. Security & Auth Flow
- **IPC Channel:** Named Pipe `\\.\pipe\curb-ipc` (unprivileged tray UI connects as standard user).
- **Read-only by default:** Status, rules, blocked events, running apps, and Steam library scan are readable without unlocking.
- **Admin Unlock:** Password verified against Argon2id hash in `C:\ProgramData\Curb\auth.json` with exponential backoff on failed attempts. Returns an in-memory 256-bit session token with 10-minute idle timeout; closing the tray window immediately revokes the token and drops the Slint window while keeping only the native `SystemTrayIcon` alive so idle RAM stays minimal.
