#!/usr/bin/env bash
set -Eeuo pipefail

# Build and package the supported client/server host for every release
# target. All staging and downloads are kept under .cache; only final
# archives and checksums are written to dist/.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CACHE_DIR="$ROOT_DIR/.cache"
DIST_DIR="$ROOT_DIR/dist"
VERSION="${WIRE_CONNECT_VERSION:-snapshot}"

usage() {
	cat >&2 <<'EOF'
usage: scripts/build-release.sh [--version VERSION]

VERSION may include the leading v from a Git tag; it is removed before being
embedded with -X main.version and before archive names are generated.
EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
		--version)
			if [[ $# -lt 2 ]]; then
				usage
				exit 2
			fi
			VERSION="$2"
			shift 2
			;;
		-h|--help)
			usage
			exit 0
			;;
		*)
			usage
			exit 2
			;;
	esac
done

VERSION="${VERSION#v}"

# The version is used in both archive paths and linker flags. Accept the
# repository's explicit snapshot marker or a complete SemVer 2.0.0 value so
# neither use can be turned into shell/path input accidentally.
SEMVER_RE='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'
if [[ "$VERSION" != snapshot && ! "$VERSION" =~ $SEMVER_RE ]]; then
	echo "release version must be snapshot or a valid SemVer (for example, 1.2.3 or 1.2.3-rc.1)" >&2
	exit 2
fi

for required in README.md LICENSE THIRD_PARTY_NOTICES.md; do
	if [[ ! -f "$ROOT_DIR/$required" ]]; then
		echo "required release file is missing: $required" >&2
		exit 1
	fi
done

mkdir -p "$CACHE_DIR/go-build" "$CACHE_DIR/go-mod" "$CACHE_DIR/tmp" "$DIST_DIR"
# dist/ is ignored and may contain output from a previous local build. Remove
# only files owned by this script, otherwise a later `dist/*` upload could
# publish an older release asset by accident.
shopt -s nullglob
for stale in \
	"$DIST_DIR"/wire-connect-*.tar.gz \
	"$DIST_DIR"/wire-connect-*.zip \
	"$DIST_DIR"/SHA256SUMS \
	"$DIST_DIR"/THIRD_PARTY_INVENTORY.txt; do
	rm -f -- "$stale"
done
shopt -u nullglob
BUILD_DIR="$(mktemp -d "$CACHE_DIR/tmp/build-release.XXXXXX")"
cleanup() {
	rm -rf "$BUILD_DIR"
}
trap cleanup EXIT

GO_ENV=(
	GOWORK=off
	GOPATH="$CACHE_DIR/go"
	GOCACHE="$CACHE_DIR/go-build"
	GOMODCACHE="$CACHE_DIR/go-mod"
	GOTMPDIR="$CACHE_DIR/tmp"
	TMPDIR="$CACHE_DIR/tmp"
)

run_go() {
	env "${GO_ENV[@]}" "$@"
}

run_go go mod verify
run_go go mod download

INVENTORY="$BUILD_DIR/THIRD_PARTY_INVENTORY.txt"
env "${GO_ENV[@]}" "$ROOT_DIR/scripts/generate-third-party-inventory.sh" "$INVENTORY"

WINTUN_STAGE="$BUILD_DIR/wintun"
"$ROOT_DIR/scripts/fetch-wintun.sh" "$WINTUN_STAGE"

build_target() {
	local target="$1"
	local goos="${target%-*}"
	local goarch="${target#*-}"
	local stage="$BUILD_DIR/$target"
	local binary="wirectl-connect"
	local archive

	if [[ "$goos" == windows ]]; then
		binary="wirectl-connect.exe"
		archive="$DIST_DIR/wire-connect-$VERSION-$target.zip"
	else
		archive="$DIST_DIR/wire-connect-$VERSION-$target.tar.gz"
	fi

	mkdir -p "$stage/bin"
	env "${GO_ENV[@]}" GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 \
		go build -trimpath -buildvcs=false \
		-ldflags="-s -w -X main.version=$VERSION" \
		-o "$stage/bin/$binary" ./cmd/wirectl-connect

	cp "$ROOT_DIR/README.md" "$ROOT_DIR/LICENSE" "$ROOT_DIR/THIRD_PARTY_NOTICES.md" "$INVENTORY" "$stage/"
	if [[ "$goos" == windows ]]; then
		cp "$WINTUN_STAGE/wintun.dll" "$WINTUN_STAGE/WINTUN-LICENSE.txt" "$stage/bin/"
		(
			cd "$stage"
			zip -q -r "$archive" bin README.md LICENSE THIRD_PARTY_NOTICES.md THIRD_PARTY_INVENTORY.txt
		)
	else
		tar -czf "$archive" -C "$stage" bin README.md LICENSE THIRD_PARTY_NOTICES.md THIRD_PARTY_INVENTORY.txt
	fi
}

# Keep this matrix aligned with the supported package matrix in README.md.
# macOS Intel is intentionally excluded; the published macOS client targets
# Apple Silicon only.
for target in linux-amd64 linux-arm64 darwin-arm64 windows-amd64; do
	build_target "$target"
done

cp "$INVENTORY" "$DIST_DIR/THIRD_PARTY_INVENTORY.txt"

checksum_file() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$@"
		return
	fi
	if command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$@"
		return
	fi
	echo "sha256sum or shasum is required" >&2
	return 1
}

(
	cd "$DIST_DIR"
	# The glob is expanded before SHA256SUMS is created, so the checksum file
	# covers every archive and the generated inventory in this build.
	checksum_file ./*.tar.gz ./*.zip ./THIRD_PARTY_INVENTORY.txt > SHA256SUMS
)

printf 'Built release %s in %s\n' "$VERSION" "$DIST_DIR"
