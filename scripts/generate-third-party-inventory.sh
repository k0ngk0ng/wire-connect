#!/usr/bin/env bash
set -Eeuo pipefail

# Emit the complete module graph used for a build. The committed
# THIRD_PARTY_NOTICES.md describes the runtime dependencies and their license
# obligations; this generated file records every transitive module and exact
# version in the release artifact.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CACHE_DIR="$ROOT_DIR/.cache"
OUTPUT="${1:-$ROOT_DIR/dist/THIRD_PARTY_INVENTORY.txt}"

case "$OUTPUT" in
	"$ROOT_DIR"/*) ;;
	*)
		echo "refusing to write inventory outside the repository: $OUTPUT" >&2
		exit 1
		;;
esac

mkdir -p "$CACHE_DIR/go-build" "$CACHE_DIR/go-mod" "$CACHE_DIR/tmp" "$(dirname "$OUTPUT")"
TMP_OUTPUT="$(mktemp "$CACHE_DIR/tmp/third-party-inventory.XXXXXX")"
cleanup() {
	if [[ -n "$TMP_OUTPUT" ]]; then
		rm -f "$TMP_OUTPUT"
	fi
}
trap cleanup EXIT

{
	printf '%s\n\n' 'wire-connect third-party module inventory'
	printf '%s\n\n' "Generated from \`go list -m all\`; module versions are resolved from go.mod/go.sum."
	printf '%s\n\n' 'The committed THIRD_PARTY_NOTICES.md lists the runtime dependency licenses. Each module below remains governed by its upstream license.'
	printf '%s\n' 'MODULE VERSION SOURCE'

	GOWORK=off \
	GOCACHE="$CACHE_DIR/go-build" \
	GOMODCACHE="$CACHE_DIR/go-mod" \
	GOTMPDIR="$CACHE_DIR/tmp" \
	TMPDIR="$CACHE_DIR/tmp" \
	go list -m -f '{{printf "%s\t%s" .Path .Version}}' all |
	while IFS=$'\t' read -r module version; do
		if [[ -z "$module" || -z "$version" || "$module" == "github.com/k0ngk0ng/wire-connect" ]]; then
			continue
		fi
		printf '%s\t%s\thttps://pkg.go.dev/%s@%s\n' "$module" "$version" "$module" "$version"
	done
} > "$TMP_OUTPUT"

mv "$TMP_OUTPUT" "$OUTPUT"
TMP_OUTPUT=""
