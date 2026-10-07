#!/bin/sh
# Download and verify SwiftLint 0.65.0, then print the absolute path to its binary.
#
# Usage: export SWIFTLINT_BIN=$(sh scripts/install-swiftlint.sh [destination-dir])
#
# The destination defaults to ${TMPDIR:-/tmp}/rootstock-swiftlint. An existing
# binary that reports the pinned version is reused without downloading.
set -eu

SWIFTLINT_VERSION=0.65.0
SWIFTLINT_SHA256=eb333bd76dfb5f46d21fdf3615fe39bb938956ca0b8e94c241c4b2db6e696b90
SWIFTLINT_URL="https://github.com/realm/SwiftLint/releases/download/${SWIFTLINT_VERSION}/SwiftLintBinary.artifactbundle.zip"

if [ "$#" -gt 1 ]; then
	echo "usage: $0 [destination-dir]" >&2
	exit 2
fi

destination=${1:-${TMPDIR:-/tmp}/rootstock-swiftlint}
mkdir -p "$destination"
destination=$(cd "$destination" && pwd)
binary="$destination/unpacked/SwiftLintBinary.artifactbundle/macos/swiftlint"

if [ -x "$binary" ] && [ "$("$binary" version 2>/dev/null)" = "$SWIFTLINT_VERSION" ]; then
	echo "$binary"
	exit 0
fi

archive="$destination/SwiftLintBinary.artifactbundle.zip"
rm -f "$archive"
curl --fail --location --proto '=https' --tlsv1.2 --silent --show-error \
	--output "$archive" "$SWIFTLINT_URL"
if ! printf '%s  %s\n' "$SWIFTLINT_SHA256" "$archive" | shasum -a 256 -c - >&2; then
	rm -f "$archive"
	echo "error: SwiftLint archive checksum mismatch" >&2
	exit 1
fi

# Extraction overwrites any stale files in place; the version check below
# rejects a destination that still holds a different binary.
if command -v ditto >/dev/null 2>&1; then
	ditto -x -k "$archive" "$destination/unpacked"
else
	unzip -q -o "$archive" -d "$destination/unpacked"
fi

if [ "$("$binary" version)" != "$SWIFTLINT_VERSION" ]; then
	echo "error: extracted SwiftLint is not version $SWIFTLINT_VERSION" >&2
	exit 1
fi
echo "$binary"
