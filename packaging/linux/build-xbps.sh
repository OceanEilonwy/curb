#!/usr/bin/env bash
set -euo pipefail

# Builds a native Void Linux `.xbps` package from prebuilt release binaries
# using Void's official `xbps-create` tool.
# Usage: ./packaging/linux/build-xbps.sh [version] [arch] [out_dir]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

VERSION="${1:-$(grep -m1 '^version' "$REPO_ROOT/Cargo.toml" | sed 's/.*"\(.*\)".*/\1/')}"
ARCH="${2:-x86_64}"
OUT_DIR="${3:-$REPO_ROOT/dist-release}"

if ! command -v xbps-create >/dev/null 2>&1; then
  echo "Error: 'xbps-create' is required (from Void Linux xbps or xbps-static)." >&2
  exit 1
fi

BIN_DIR="$REPO_ROOT/target/release"
for bin in curb-app curb-cli curb-service; do
  if [[ ! -x "$BIN_DIR/$bin" ]]; then
    echo "Error: missing release binary $BIN_DIR/$bin. Run 'cargo build --release --workspace' first." >&2
    exit 1
  fi
done

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

install -Dm755 "$BIN_DIR/curb-app" "$STAGE/usr/bin/curb-app"
install -Dm755 "$BIN_DIR/curb-cli" "$STAGE/usr/bin/curb-cli"
install -Dm755 "$BIN_DIR/curb-service" "$STAGE/usr/libexec/curb/curb-service"
install -Dm644 "$SCRIPT_DIR/curb.desktop" "$STAGE/usr/share/applications/curb.desktop"
install -Dm644 "$SCRIPT_DIR/org.curb.policy" "$STAGE/usr/share/polkit-1/actions/org.curb.policy"
install -Dm644 "$REPO_ROOT/apps/curb-app/icons/128x128.png" "$STAGE/usr/share/icons/hicolor/128x128/apps/curb.png"
install -Dm644 "$REPO_ROOT/apps/curb-app/icons/32x32.png" "$STAGE/usr/share/icons/hicolor/32x32/apps/curb.png"
install -Dm644 "$REPO_ROOT/LICENSE" "$STAGE/usr/share/licenses/curb/LICENSE"
install -Dm755 "$SCRIPT_DIR/runit/run" "$STAGE/etc/sv/curb/run"
install -Dm755 "$SCRIPT_DIR/runit/log-run" "$STAGE/etc/sv/curb/log/run"
install -Dm755 "$SCRIPT_DIR/void/INSTALL" "$STAGE/INSTALL"
install -Dm755 "$SCRIPT_DIR/void/REMOVE" "$STAGE/REMOVE"

mkdir -p "$OUT_DIR"
OUT_ABS="$(cd "$OUT_DIR" && pwd)"

(
  cd "$OUT_ABS"
  xbps-create \
    -A "$ARCH" \
    -n "curb-${VERSION}_1" \
    -s "Default-deny application internet limiter (nftables + NFQUEUE + Slint UI)" \
    -l "AGPL-3.0-or-later" \
    -H "https://github.com/OceanEilonwy/curb" \
    -m "Curb Maintainers <https://github.com/OceanEilonwy/curb>" \
    -D "nftables>=0 polkit>=0 fontconfig>=0" \
    "$STAGE"
)

echo "Built $OUT_ABS/curb-${VERSION}_1.${ARCH}.xbps"
