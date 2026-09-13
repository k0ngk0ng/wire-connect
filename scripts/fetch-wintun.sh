#!/usr/bin/env bash
set -Eeuo pipefail

# Wintun is distributed as a separate official Windows runtime. Keep the
# download in the repository cache and copy only the x64 runtime and its
# upstream license into a release staging directory.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CACHE_DIR="$ROOT_DIR/.cache"
WINTUN_VERSION="0.14.1"
WINTUN_URL="https://www.wintun.net/builds/wintun-${WINTUN_VERSION}.zip"
WINTUN_SHA256="07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"

if [[ $# -ne 1 ]]; then
	echo "usage: $0 <release-staging-directory>" >&2
	exit 2
fi

DEST_DIR="$1"
case "$DEST_DIR" in
	"$ROOT_DIR"/*) ;;
	*)
		echo "refusing to write Wintun outside the repository: $DEST_DIR" >&2
		exit 1
		;;
esac

mkdir -p "$CACHE_DIR/wintun" "$CACHE_DIR/tmp" "$DEST_DIR"

sha256_file() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
		return
	fi
	if command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | awk '{print $1}'
		return
	fi
	echo "sha256sum or shasum is required" >&2
	return 1
}

verify_archive() {
	local archive="$1"
	local actual
	actual="$(sha256_file "$archive")"
	if [[ "$(printf '%s' "$actual" | tr '[:upper:]' '[:lower:]')" != "$WINTUN_SHA256" ]]; then
		echo "Wintun archive checksum mismatch" >&2
		echo "  expected: $WINTUN_SHA256" >&2
		echo "  actual:   $actual" >&2
		return 1
	fi
}

ARCHIVE="$CACHE_DIR/wintun/wintun-${WINTUN_VERSION}.zip"
DOWNLOAD_TMP=""
EXTRACT_DIR=""
cleanup() {
	if [[ -n "$DOWNLOAD_TMP" ]]; then
		rm -f "$DOWNLOAD_TMP"
	fi
	if [[ -n "$EXTRACT_DIR" ]]; then
		rm -rf "$EXTRACT_DIR"
	fi
}
trap cleanup EXIT

if [[ -f "$ARCHIVE" ]]; then
	verify_archive "$ARCHIVE"
else
	DOWNLOAD_TMP="$(mktemp "$CACHE_DIR/tmp/wintun-download.XXXXXX")"
	curl --fail --location --proto '=https' --tlsv1.2 --retry 3 \
		--connect-timeout 20 --output "$DOWNLOAD_TMP" "$WINTUN_URL"
	verify_archive "$DOWNLOAD_TMP"
	mv "$DOWNLOAD_TMP" "$ARCHIVE"
	DOWNLOAD_TMP=""
fi

EXTRACT_DIR="$(mktemp -d "$CACHE_DIR/tmp/wintun-extract.XXXXXX")"
unzip -q "$ARCHIVE" -d "$EXTRACT_DIR"

DLL="$EXTRACT_DIR/wintun/bin/amd64/wintun.dll"
LICENSE="$EXTRACT_DIR/wintun/LICENSE.txt"
if [[ ! -f "$DLL" || ! -f "$LICENSE" ]]; then
	echo "Wintun archive is missing the official x64 DLL or license" >&2
	exit 1
fi

cp "$DLL" "$DEST_DIR/wintun.dll"
cp "$LICENSE" "$DEST_DIR/WINTUN-LICENSE.txt"
printf 'Wintun %s verified (%s)\n' "$WINTUN_VERSION" "$WINTUN_SHA256" >&2
