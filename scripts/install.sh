#!/usr/bin/env sh
# Install a released bsc binary for the current user and verify its checksum
# against the SHA256SUMS published with the same release.
#
#   sh install.sh v0.2.0            # specific version (recommended)
#   BSC_BIN_DIR=~/bin sh install.sh v0.2.0
#
# This checks integrity: the archive matches the sums published beside it. It
# does not by itself check who built it, because both come from the same
# release page. From v0.2.0 the sums are signed with Sigstore as well —
# SECURITY.md has the `cosign verify-blob` command and says what it proves.
# Read this file before running it; do not pipe it from the network into a
# shell.
set -eu

REPO="yamantaka520/Bastet-Secret-Chain"
VERSION="${1:-}"
BIN_DIR="${BSC_BIN_DIR:-$HOME/.local/bin}"

[ -n "$VERSION" ] || { echo "usage: install.sh vX.Y.Z" >&2; exit 2; }

os=$(uname -s); arch=$(uname -m)
case "$os-$arch" in
  Darwin-arm64)  target=aarch64-apple-darwin ;;
  Darwin-x86_64) target=x86_64-apple-darwin ;;
  Linux-x86_64)  target=x86_64-unknown-linux-gnu ;;
  *) echo "no prebuilt binary for $os $arch; build from source with cargo" >&2; exit 1 ;;
esac

name="bsc-${VERSION#v}-${target}"
base="https://github.com/$REPO/releases/download/$VERSION"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

echo "downloading $name.tar.gz"
curl -fsSL -o "$tmp/$name.tar.gz" "$base/$name.tar.gz"
curl -fsSL -o "$tmp/SHA256SUMS" "$base/SHA256SUMS"
( cd "$tmp" && grep " $name.tar.gz\$" SHA256SUMS | sha256sum -c - ) || {
  echo "checksum mismatch — refusing to install" >&2; exit 1; }

tar xzf "$tmp/$name.tar.gz" -C "$tmp"
mkdir -p "$BIN_DIR"
install -m 0755 "$tmp/$name/bsc" "$BIN_DIR/bsc"
echo "installed $BIN_DIR/bsc"
"$BIN_DIR/bsc" --version
case ":$PATH:" in *":$BIN_DIR:"*) ;; *) echo "note: add $BIN_DIR to your PATH" ;; esac
echo
echo "next:  bsc init  &&  bsc service install  &&  open http://127.0.0.1:8787/"
