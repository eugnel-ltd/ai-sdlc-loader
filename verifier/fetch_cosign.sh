#!/bin/sh
# Fetch the pinned cosign verifier and copy its pinned trusted root.
set -u

die() {
  echo "fetch_cosign.sh: $*" >&2
  exit 1
}

usage() {
  echo "usage: fetch_cosign.sh <dest-dir>" >&2
  exit 2
}

[ "$#" -eq 1 ] || usage
dest=$1
here=$(CDPATH= cd "$(dirname "$0")" && pwd) || die "cannot find the verifier directory"
pins=$here/pins.txt
trusted_root=$here/trusted_root.json

if [ -n "${COSIGN_PLATFORM:-}" ]; then
  platform=$COSIGN_PLATFORM
else
  system=$(uname -s) || { echo "fetch_cosign.sh: cannot detect the operating system" >&2; exit 2; }
  machine=$(uname -m) || { echo "fetch_cosign.sh: cannot detect the machine architecture" >&2; exit 2; }
  case "$system:$machine" in
    Linux:aarch64|Linux:arm64) platform=linux-arm64 ;;
    Linux:x86_64|Linux:amd64) platform=linux-amd64 ;;
    Darwin:arm64|Darwin:aarch64) platform=darwin-arm64 ;;
    *) echo "fetch_cosign.sh: unsupported platform: $system/$machine" >&2; exit 2 ;;
  esac
fi

case "$platform" in
  linux-arm64|linux-amd64|darwin-arm64) ;;
  *) echo "fetch_cosign.sh: unsupported platform: $platform" >&2; exit 2 ;;
esac

[ -f "$pins" ] || die "pins file is missing: $pins"
[ -f "$trusted_root" ] || die "trusted root is missing: $trusted_root"
command -v curl >/dev/null 2>&1 || die "curl is not available"

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    die "no SHA-256 command is available"
  fi
}

pin_for() {
  awk -v name="$1" '
    $2 == name { digest = $1; count++ }
    END { if (count == 1) print digest; else exit 1 }
  ' "$pins"
}

binary=cosign-$platform
expected_cosign=$(pin_for "$binary") || die "one pin is required for $binary"
expected_root=$(pin_for trusted_root.json) || die "one pin is required for trusted_root.json"

actual_root=$(sha256_file "$trusted_root") || die "cannot hash trusted_root.json"
[ "$actual_root" = "$expected_root" ] || die "SHA-256 mismatch for trusted_root.json"

stage=$(mktemp -d "${TMPDIR:-/tmp}/fetch-cosign.XXXXXX") || die "cannot create a temporary directory"
trap 'rm -rf "$stage"' EXIT HUP INT TERM

if [ -n "${COSIGN_URL_BASE:-}" ]; then
  case "$COSIGN_URL_BASE" in
    file://*) url=${COSIGN_URL_BASE%/}/$binary ;;
    *)
      base=$(CDPATH= cd "$COSIGN_URL_BASE" 2>/dev/null && pwd) || die "local COSIGN_URL_BASE is not a directory"
      url=file://${base%/}/$binary
      ;;
  esac
  curl -fsSL --proto '=file' "$url" -o "$stage/cosign" || die "download failed for $url"
else
  url=https://github.com/sigstore/cosign/releases/download/v3.1.4/$binary
  curl -fsSL --proto '=https' "$url" -o "$stage/cosign" || die "download failed for $url"
fi

actual_cosign=$(sha256_file "$stage/cosign") || die "cannot hash $binary"
[ "$actual_cosign" = "$expected_cosign" ] || die "SHA-256 mismatch for $binary"

cp "$trusted_root" "$stage/trusted_root.json" || die "cannot stage trusted_root.json"
chmod 755 "$stage/cosign" || die "cannot set cosign executable mode"
mkdir -p "$dest" || die "cannot create destination: $dest"
[ ! -e "$dest/cosign" ] || die "destination already has cosign"
[ ! -e "$dest/trusted_root.json" ] || die "destination already has trusted_root.json"

published=0
trap '[ "$published" -eq 1 ] || rm -f "$dest/cosign" "$dest/trusted_root.json"; rm -rf "$stage"' EXIT HUP INT TERM
mv "$stage/cosign" "$dest/cosign" || die "cannot install cosign"
mv "$stage/trusted_root.json" "$dest/trusted_root.json" || die "cannot install trusted_root.json"
published=1
exit 0
