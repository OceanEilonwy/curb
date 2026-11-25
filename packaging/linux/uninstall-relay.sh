#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Please run as root (e.g. sudo ./uninstall-relay.sh)" >&2
  exit 1
fi

if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
  systemctl disable --now curb-relay.service 2>/dev/null || true
fi

rm -f /usr/bin/curb-relay /usr/lib/systemd/system/curb-relay.service
rm -rf /usr/share/doc/curb-relay

if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
  systemctl daemon-reload
fi

echo "Uninstalled curb-relay."
