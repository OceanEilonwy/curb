#!/usr/bin/env bash
set -euo pipefail

# Builds a Debian/Ubuntu/Mint/Pop!_OS .deb package from prebuilt release binaries.
# Usage: ./packaging/linux/build-deb.sh [version] [arch] [out_dir]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

VERSION="${1:-$(grep -m1 '^version' "$REPO_ROOT/Cargo.toml" | sed 's/.*"\(.*\)".*/\1/')}"
ARCH="${2:-amd64}"
OUT_DIR="${3:-$REPO_ROOT/dist-release}"

BIN_DIR="$REPO_ROOT/target/release"
for bin in curb-app curb-cli curb-service; do
  if [[ ! -x "$BIN_DIR/$bin" ]]; then
    echo "Error: missing release binary $BIN_DIR/$bin. Run 'cargo build --release --workspace' first." >&2
    exit 1
  fi
done

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

mkdir -p \
  "$STAGE/DEBIAN" \
  "$STAGE/usr/bin" \
  "$STAGE/usr/libexec/curb" \
  "$STAGE/usr/lib/systemd/system" \
  "$STAGE/usr/share/applications" \
  "$STAGE/usr/share/icons/hicolor/128x128/apps" \
  "$STAGE/usr/share/icons/hicolor/32x32/apps" \
  "$STAGE/usr/share/icons/hicolor/scalable/apps" \
  "$STAGE/usr/share/polkit-1/actions" \
  "$STAGE/usr/share/doc/curb"

install -m 0755 "$BIN_DIR/curb-app" "$STAGE/usr/bin/curb-app"
install -m 0755 "$BIN_DIR/curb-cli" "$STAGE/usr/bin/curb-cli"
install -m 0755 "$BIN_DIR/curb-service" "$STAGE/usr/libexec/curb/curb-service"
install -m 0644 "$SCRIPT_DIR/curb.service" "$STAGE/usr/lib/systemd/system/curb.service"
install -m 0644 "$SCRIPT_DIR/curb.desktop" "$STAGE/usr/share/applications/curb.desktop"
install -m 0644 "$SCRIPT_DIR/org.curb.policy" "$STAGE/usr/share/polkit-1/actions/org.curb.policy"
install -m 0644 "$REPO_ROOT/apps/curb-app/icons/128x128.png" "$STAGE/usr/share/icons/hicolor/128x128/apps/curb.png"
install -m 0644 "$REPO_ROOT/apps/curb-app/icons/32x32.png" "$STAGE/usr/share/icons/hicolor/32x32/apps/curb.png"
install -m 0644 "$REPO_ROOT/apps/curb-app/icons/icon.svg" "$STAGE/usr/share/icons/hicolor/scalable/apps/curb.svg"
install -m 0644 "$REPO_ROOT/LICENSE" "$STAGE/usr/share/doc/curb/LICENSE"
install -m 0644 "$REPO_ROOT/README.md" "$STAGE/usr/share/doc/curb/README.md"

cat > "$STAGE/DEBIAN/control" <<EOF
Package: curb
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Maintainer: Curb Maintainers <https://github.com/OceanEilonwy/curb>
Depends: nftables, libfontconfig1, polkitd | policykit-1
Homepage: https://github.com/OceanEilonwy/curb
Description: Default-deny application internet limiter
 Curb blocks all outbound traffic by default at the OS firewall (nftables +
 NFQUEUE) and allows only explicitly approved apps, games, and DNS whitelists.
EOF

cat > "$STAGE/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "configure" ]; then
  command -v curb-cli >/dev/null 2>&1 && curb-cli upgrade >/dev/null 2>&1 || true
  if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor || true
  fi
fi
exit 0
EOF
chmod 0755 "$STAGE/DEBIAN/postinst"

cat > "$STAGE/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "purge" ]; then
  command -v curb-cli >/dev/null 2>&1 && curb-cli uninstall --purge || true
elif [ "$1" = "remove" ]; then
  command -v curb-cli >/dev/null 2>&1 && curb-cli uninstall || true
fi
exit 0
EOF
chmod 0755 "$STAGE/DEBIAN/prerm"

mkdir -p "$OUT_DIR"
DEB_PATH="$OUT_DIR/curb_${VERSION}_${ARCH}.deb"
dpkg-deb --root-owner-group --build "$STAGE" "$DEB_PATH"
echo "Built $DEB_PATH"
