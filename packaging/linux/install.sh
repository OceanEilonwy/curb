#!/usr/bin/env bash
set -euo pipefail

# Universal Linux installer for any systemd + nftables distribution.
# Run as root (e.g. `sudo ./install.sh`) from an extracted Curb Linux tarball.

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Please run as root: sudo $0" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! command -v nft >/dev/null 2>&1; then
  echo "Warning: 'nft' (nftables) was not found on PATH." >&2
  echo "Install nftables with your distro's package manager (apt/dnf/pacman/zypper) before enabling Full Protection." >&2
fi

install -Dm755 "$SCRIPT_DIR/curb-app" /usr/bin/curb-app
install -Dm755 "$SCRIPT_DIR/curb-cli" /usr/bin/curb-cli
install -Dm755 "$SCRIPT_DIR/curb-service" /usr/libexec/curb/curb-service
install -Dm644 "$SCRIPT_DIR/curb.service" /usr/lib/systemd/system/curb.service
install -Dm644 "$SCRIPT_DIR/curb.desktop" /usr/share/applications/curb.desktop
install -Dm644 "$SCRIPT_DIR/org.curb.policy" /usr/share/polkit-1/actions/org.curb.policy
install -Dm644 "$SCRIPT_DIR/icon-128.png" /usr/share/icons/hicolor/128x128/apps/curb.png
install -Dm644 "$SCRIPT_DIR/icon-32.png" /usr/share/icons/hicolor/32x32/apps/curb.png

if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
  systemctl daemon-reload
fi

echo "Curb installed successfully!"
echo "Launch 'Curb' from your application menu (or run 'curb-app'),"
echo "or enable Full Protection from the terminal with: sudo curb-cli install"
