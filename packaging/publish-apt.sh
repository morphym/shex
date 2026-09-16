#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: publish-apt.sh ARTIFACT_DIR SITE_DIR" >&2
  exit 2
fi

artifact_dir=$(cd "$1" && pwd)
site_dir=$(cd "$2" && pwd)
pool_dir="$site_dir/apt/pool/main/s/shex"
dist_dir="$site_dir/apt/dists/stable"

mkdir -p "$pool_dir"
cp "$artifact_dir"/shex_*_amd64.deb "$pool_dir/"
cp "$artifact_dir"/shex_*_arm64.deb "$pool_dir/"

for architecture in amd64 arm64; do
  package_dir="$dist_dir/main/binary-$architecture"
  mkdir -p "$package_dir"
  (
    cd "$site_dir/apt"
    apt-ftparchive packages --arch "$architecture" pool/main \
      >"dists/stable/main/binary-$architecture/Packages"
    gzip -9c "dists/stable/main/binary-$architecture/Packages" \
      >"dists/stable/main/binary-$architecture/Packages.gz"
  )
done

(
  cd "$site_dir/apt"
  apt-ftparchive \
    -o APT::FTPArchive::Release::Origin="shex" \
    -o APT::FTPArchive::Release::Label="shex" \
    -o APT::FTPArchive::Release::Suite="stable" \
    -o APT::FTPArchive::Release::Codename="stable" \
    -o APT::FTPArchive::Release::Architectures="amd64 arm64" \
    -o APT::FTPArchive::Release::Components="main" \
    -o APT::FTPArchive::Release::Description="shex native packages" \
    release dists/stable >dists/stable/Release
  gpg --batch --yes --armor --detach-sign \
    --output dists/stable/Release.gpg dists/stable/Release
  gpg --batch --yes --clearsign \
    --output dists/stable/InRelease dists/stable/Release
  gpg --batch --yes --export >shex-archive-keyring.gpg
)

touch "$site_dir/.nojekyll"
