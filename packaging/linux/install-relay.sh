#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Please run as root (e.g. sudo ./install-relay.sh)" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

install -Dm755 "$SCRIPT_DIR/curb-relay" /usr/bin/curb-relay
install -Dm644 "$SCRIPT_DIR/curb-relay.service" /usr/lib/systemd/system/curb-relay.service
install -Dm644 "$SCRIPT_DIR/curb-relay.env.example" /usr/share/doc/curb-relay/curb-relay.env.example

if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
  systemctl daemon-reload
  echo "Installed curb-relay. Enable and start with: sudo systemctl enable --now curb-relay"
else
  echo "Installed curb-relay to /usr/bin/curb-relay"
fi
