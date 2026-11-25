#!/usr/bin/env bash
set -euo pipefail

# Builds an Arch Linux / CachyOS / Manjaro / EndeavourOS / SteamOS `.pkg.tar.zst`
# package from prebuilt release binaries without requiring a full Arch container.
# Usage: ./packaging/linux/build-arch.sh [version] [arch] [out_dir]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

VERSION="${1:-$(grep -m1 '^version' "$REPO_ROOT/Cargo.toml" | sed 's/.*"\(.*\)".*/\1/')}"
ARCH="${2:-x86_64}"
OUT_DIR="${3:-$REPO_ROOT/dist-release}"

for tool in bsdtar zstd; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "Error: '$tool' is required (install libarchive-tools and zstd)." >&2
    exit 1
  fi
done

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
install -Dm644 "$SCRIPT_DIR/curb.service" "$STAGE/usr/lib/systemd/system/curb.service"
install -Dm644 "$SCRIPT_DIR/curb.desktop" "$STAGE/usr/share/applications/curb.desktop"
install -Dm644 "$SCRIPT_DIR/org.curb.policy" "$STAGE/usr/share/polkit-1/actions/org.curb.policy"
install -Dm644 "$REPO_ROOT/apps/curb-app/icons/128x128.png" "$STAGE/usr/share/icons/hicolor/128x128/apps/curb.png"
install -Dm644 "$REPO_ROOT/apps/curb-app/icons/32x32.png" "$STAGE/usr/share/icons/hicolor/32x32/apps/curb.png"
install -Dm644 "$REPO_ROOT/LICENSE" "$STAGE/usr/share/licenses/curb/LICENSE"
install -Dm644 "$SCRIPT_DIR/curb.install" "$STAGE/.INSTALL"

INSTALLED_SIZE="$(du -sb "$STAGE/usr" | awk '{print $1}')"
BUILD_DATE="$(date -u +%s)"

cat > "$STAGE/.PKGINFO" <<EOF
pkgname = curb
pkgbase = curb
pkgver = ${VERSION}-1
pkgdesc = Default-deny application internet limiter (nftables + NFQUEUE + Slint UI)
url = https://github.com/OceanEilonwy/curb
builddate = ${BUILD_DATE}
packager = Curb Maintainers <https://github.com/OceanEilonwy/curb>
size = ${INSTALLED_SIZE}
arch = ${ARCH}
license = AGPL-3.0-or-later
depend = nftables
depend = polkit
depend = fontconfig
optdepend = polkit-kde-agent: graphical elevation prompt on KDE Plasma
optdepend = polkit-gnome: graphical elevation prompt on XFCE, Sway, Mango, or dwl
optdepend = waybar: system tray support on Sway, Mango, and dwl
EOF

mkdir -p "$OUT_DIR"
OUT_ABS="$(cd "$OUT_DIR" && pwd)"
PKG_PATH="$OUT_ABS/curb-${VERSION}-1-${ARCH}.pkg.tar.zst"

(
  cd "$STAGE"
  LANG=C bsdtar -czf .MTREE \
    --format=mtree \
    --options='!all,use-set,type,uid,gid,mode,time,size,md5,sha256,link' \
    --uid 0 --gid 0 --uname root --gname root \
    .PKGINFO .INSTALL usr

  LANG=C bsdtar -cf - \
    --uid 0 --gid 0 --uname root --gname root \
    .PKGINFO .MTREE .INSTALL usr \
    | zstd -c -T0 -19 > "$PKG_PATH"
)

echo "Built $PKG_PATH"
