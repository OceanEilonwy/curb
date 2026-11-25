#!/usr/bin/env bash
set -euo pipefail

# Builds a Debian/Ubuntu/Mint/Pop!_OS .deb package for curb-relay.
# Usage: ./packaging/linux/build-relay-deb.sh [version] [arch] [out_dir]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

VERSION="${1:-$(grep -m1 '^version' "$REPO_ROOT/Cargo.toml" | sed 's/.*"\(.*\)".*/\1/')}"
ARCH="${2:-amd64}"
OUT_DIR="${3:-$REPO_ROOT/dist-release}"

BIN="$REPO_ROOT/target/release/curb-relay"
if [[ ! -x "$BIN" ]]; then
  echo "Error: missing release binary $BIN. Run 'cargo build --release -p curb-relay' first." >&2
  exit 1
fi

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

mkdir -p \
  "$STAGE/DEBIAN" \
  "$STAGE/usr/bin" \
  "$STAGE/usr/lib/systemd/system" \
  "$STAGE/usr/share/doc/curb-relay"

install -m 0755 "$BIN" "$STAGE/usr/bin/curb-relay"
install -m 0644 "$SCRIPT_DIR/curb-relay.service" "$STAGE/usr/lib/systemd/system/curb-relay.service"
install -m 0644 "$SCRIPT_DIR/curb-relay.env.example" "$STAGE/usr/share/doc/curb-relay/curb-relay.env.example"
install -m 0644 "$REPO_ROOT/LICENSE" "$STAGE/usr/share/doc/curb-relay/LICENSE"
install -m 0644 "$REPO_ROOT/README.md" "$STAGE/usr/share/doc/curb-relay/README.md"

cat > "$STAGE/DEBIAN/control" <<EOF
Package: curb-relay
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Maintainer: Curb Maintainers <https://github.com/OceanEilonwy/curb>
Homepage: https://github.com/OceanEilonwy/curb
Description: Zero-knowledge P2P relay and encrypted backup server for Curb
 Self-hostable rendezvous relay proxy and optional end-to-end encrypted
 settings backup server for Curb cross-device sync and remote administration.
EOF

cat > "$STAGE/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "configure" ]; then
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
  fi
fi
exit 0
EOF
chmod 0755 "$STAGE/DEBIAN/postinst"

cat > "$STAGE/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl disable --now curb-relay.service || true
  fi
fi
exit 0
EOF
chmod 0755 "$STAGE/DEBIAN/prerm"

mkdir -p "$OUT_DIR"
DEB_PATH="$OUT_DIR/curb-relay_${VERSION}_${ARCH}.deb"
dpkg-deb --root-owner-group --build "$STAGE" "$DEB_PATH"
echo "Built $DEB_PATH"
