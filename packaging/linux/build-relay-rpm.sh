#!/usr/bin/env bash
set -euo pipefail

# Builds a Fedora/RHEL/openSUSE .rpm package for curb-relay.
# Usage: ./packaging/linux/build-relay-rpm.sh [version] [arch] [out_dir]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

VERSION="${1:-$(grep -m1 '^version' "$REPO_ROOT/Cargo.toml" | sed 's/.*"\(.*\)".*/\1/')}"
ARCH="${2:-x86_64}"
OUT_DIR="${3:-$REPO_ROOT/dist-release}"

BIN="$REPO_ROOT/target/release/curb-relay"
if [[ ! -x "$BIN" ]]; then
  echo "Error: missing release binary $BIN. Run 'cargo build --release -p curb-relay' first." >&2
  exit 1
fi

TOPDIR="$(mktemp -d)"
trap 'rm -rf "$TOPDIR"' EXIT
mkdir -p "$TOPDIR"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

cp "$BIN" "$TOPDIR/SOURCES/"
cp "$SCRIPT_DIR/curb-relay.service" "$TOPDIR/SOURCES/"
cp "$SCRIPT_DIR/curb-relay.env.example" "$TOPDIR/SOURCES/"
cp "$REPO_ROOT/LICENSE" "$TOPDIR/SOURCES/"
cp "$REPO_ROOT/README.md" "$TOPDIR/SOURCES/"
cp "$SCRIPT_DIR/curb-relay.spec" "$TOPDIR/SPECS/"

rpmbuild \
  --define "_topdir $TOPDIR" \
  --define "_version $VERSION" \
  --define "debug_package %{nil}" \
  --target "$ARCH" \
  -bb "$TOPDIR/SPECS/curb-relay.spec"

mkdir -p "$OUT_DIR"
RPM_FILE="$(find "$TOPDIR/RPMS" -name '*.rpm' | head -n1)"
cp "$RPM_FILE" "$OUT_DIR/curb-relay-${VERSION}-1.${ARCH}.rpm"
echo "Built $OUT_DIR/curb-relay-${VERSION}-1.${ARCH}.rpm"
