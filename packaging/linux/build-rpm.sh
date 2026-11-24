#!/usr/bin/env bash
set -euo pipefail

# Builds a Fedora/RHEL/openSUSE .rpm package from prebuilt release binaries.
# Usage: ./packaging/linux/build-rpm.sh [version] [arch] [out_dir]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

VERSION="${1:-$(grep -m1 '^version' "$REPO_ROOT/Cargo.toml" | sed 's/.*"\(.*\)".*/\1/')}"
ARCH="${2:-x86_64}"
OUT_DIR="${3:-$REPO_ROOT/dist-release}"

BIN_DIR="$REPO_ROOT/target/release"
for bin in curb-app curb-cli curb-service; do
  if [[ ! -x "$BIN_DIR/$bin" ]]; then
    echo "Error: missing release binary $BIN_DIR/$bin. Run 'cargo build --release --workspace' first." >&2
    exit 1
  fi
done

TOPDIR="$(mktemp -d)"
trap 'rm -rf "$TOPDIR"' EXIT
mkdir -p "$TOPDIR"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

cp "$BIN_DIR/curb-app" "$TOPDIR/SOURCES/"
cp "$BIN_DIR/curb-cli" "$TOPDIR/SOURCES/"
cp "$BIN_DIR/curb-service" "$TOPDIR/SOURCES/"
cp "$SCRIPT_DIR/curb.service" "$TOPDIR/SOURCES/"
cp "$SCRIPT_DIR/curb.desktop" "$TOPDIR/SOURCES/"
cp "$SCRIPT_DIR/org.curb.policy" "$TOPDIR/SOURCES/"
cp "$REPO_ROOT/apps/curb-app/icons/128x128.png" "$TOPDIR/SOURCES/icon-128.png"
cp "$REPO_ROOT/apps/curb-app/icons/32x32.png" "$TOPDIR/SOURCES/icon-32.png"
cp "$REPO_ROOT/LICENSE" "$TOPDIR/SOURCES/"
cp "$REPO_ROOT/README.md" "$TOPDIR/SOURCES/"
cp "$SCRIPT_DIR/curb.spec" "$TOPDIR/SPECS/"

rpmbuild \
  --define "_topdir $TOPDIR" \
  --define "_version $VERSION" \
  --define "debug_package %{nil}" \
  --target "$ARCH" \
  -bb "$TOPDIR/SPECS/curb.spec"

mkdir -p "$OUT_DIR"
RPM_FILE="$(find "$TOPDIR/RPMS" -name '*.rpm' | head -n1)"
cp "$RPM_FILE" "$OUT_DIR/curb-${VERSION}-1.${ARCH}.rpm"
echo "Built $OUT_DIR/curb-${VERSION}-1.${ARCH}.rpm"
