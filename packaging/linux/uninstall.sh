#!/usr/bin/env bash
set -euo pipefail

# Universal Linux uninstaller for Curb.
# Run as root: `sudo ./uninstall.sh`

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Please run as root: sudo $0" >&2
  exit 1
fi

if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
  systemctl disable --now curb.service 2>/dev/null || true
fi

if command -v nft >/dev/null 2>&1; then
  nft delete table inet curb 2>/dev/null || true
fi

rm -f \
  /usr/bin/curb-app \
  /usr/bin/curb-cli \
  /usr/libexec/curb/curb-service \
  /usr/lib/systemd/system/curb.service \
  /etc/systemd/system/curb.service \
  /usr/share/applications/curb.desktop \
  /usr/share/polkit-1/actions/org.curb.policy \
  /usr/share/icons/hicolor/128x128/apps/curb.png \
  /usr/share/icons/hicolor/32x32/apps/curb.png
rmdir /usr/libexec/curb 2>/dev/null || true

if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
  systemctl daemon-reload
fi

echo "Curb uninstalled and Linux firewall rules restored."
