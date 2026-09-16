#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: build-deb.sh BINARY VERSION ARCH OUTPUT_DIR" >&2
  exit 2
fi

binary=$1
version=$2
architecture=$3
output_dir=$4
package_root=$(mktemp -d)
trap 'rm -rf "$package_root"' EXIT

install -Dm755 "$binary" "$package_root/usr/bin/shex"
install -Dm644 README.md "$package_root/usr/share/doc/shex/README.md"
mkdir -p "$package_root/DEBIAN"

installed_size=$(du -sk "$package_root/usr" | cut -f1)
cat >"$package_root/DEBIAN/control" <<EOF
Package: shex
Version: $version
Section: net
Priority: optional
Architecture: $architecture
Maintainer: morphym <noreply@github.com>
Depends: libc6 (>= 2.35), libgcc-s1
Installed-Size: $installed_size
Homepage: https://github.com/morphym/shex
Description: OPAQUE-authenticated, end-to-end encrypted Redis remote shell
 shex provides encrypted remote shell sessions routed through Redis without
 exposing authentication codes, commands, output, or shell state to Redis.
EOF

mkdir -p "$output_dir"
dpkg-deb --root-owner-group --build "$package_root" \
  "$output_dir/shex_${version}_${architecture}.deb"
