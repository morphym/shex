#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
usage: prepare-launchpad-source.sh [--unsigned] SERIES OUTPUT_DIR

Build a Launchpad source upload. Set DEBSIGN_KEYID to the fingerprint of the
OpenPGP key registered with Launchpad unless --unsigned is used for testing.

Example:
  DEBSIGN_KEYID=0123456789ABCDEF packaging/prepare-launchpad-source.sh noble dist/launchpad
EOF
}

unsigned=false
if [[ ${1:-} == "--unsigned" ]]; then
  unsigned=true
  shift
fi

if [[ $# -ne 2 ]]; then
  usage >&2
  exit 2
fi

series=$1
output_dir=$(mkdir -p "$2" && cd "$2" && pwd)
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$repo_root/Cargo.toml" | head -1)

if [[ -z "$version" ]]; then
  echo "could not read the package version from Cargo.toml" >&2
  exit 1
fi

if ! [[ "$series" =~ ^[a-z][a-z0-9-]*$ ]]; then
  echo "invalid Ubuntu series: $series" >&2
  exit 2
fi

if ! $unsigned && [[ -z ${DEBSIGN_KEYID:-} ]]; then
  echo "DEBSIGN_KEYID must name the OpenPGP key registered with Launchpad" >&2
  exit 2
fi

for command in debuild git; do
  if ! command -v "$command" >/dev/null; then
    echo "required command not found: $command" >&2
    exit 1
  fi
done

cargo_command=${CARGO:-cargo}
if [[ -x /usr/lib/rust-1.89/bin/cargo ]]; then
  cargo_command=/usr/lib/rust-1.89/bin/cargo
fi
if ! command -v "$cargo_command" >/dev/null; then
  echo "required Cargo executable not found: $cargo_command" >&2
  exit 1
fi

work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT
source_dir="$work_dir/shex-$version"
mkdir -p "$source_dir"

git -C "$repo_root" archive HEAD | tar -x -C "$source_dir"
mkdir -p "$source_dir/.cargo"
(
  cd "$source_dir"
  "$cargo_command" vendor --locked vendor >.cargo/config.toml
)

tar -C "$work_dir" -czf "$work_dir/shex_${version}.orig.tar.gz" "shex-$version"
cp -R "$repo_root/packaging/launchpad/debian" "$source_dir/debian"

release_date=$(LC_ALL=C date -R)
sed \
  -e "s/@VERSION@/$version/g" \
  -e "s/@SERIES@/$series/g" \
  -e "s/@DATE@/$release_date/g" \
  "$source_dir/debian/changelog.in" >"$source_dir/debian/changelog"
rm "$source_dir/debian/changelog.in"
chmod +x "$source_dir/debian/rules"

build_args=(-S -sa -d)
if $unsigned; then
  build_args+=(-us -uc)
else
  build_args+=("-k$DEBSIGN_KEYID")
fi

(
  cd "$source_dir"
  debuild "${build_args[@]}"
)

find "$work_dir" -maxdepth 1 -type f \
  \( -name "shex_${version}*.changes" -o \
     -name "shex_${version}*.dsc" -o \
     -name "shex_${version}*.tar.*" \) \
  -exec cp {} "$output_dir/" \;

echo "Launchpad source upload written to $output_dir"
if $unsigned; then
  echo "This test bundle is unsigned and cannot be uploaded to Launchpad."
else
  echo "Upload with: dput ppa:LAUNCHPAD_USER/PPA_NAME $output_dir/shex_${version}-0ubuntu1~${series}1_source.changes"
fi
