#!/bin/bash
set -euo pipefail

VERSION="${1:-0.1.0}"
OUTPUT_DIR="release"
BINARY_NAME="rootstock-collector-v${VERSION}"

echo "Building Rootstock Collector v${VERSION} (Universal Binary)..."

cd "$(dirname "$0")/../collector"

# Build for both architectures
swift build -c release --arch arm64 --arch x86_64

# Copy binary
mkdir -p "../${OUTPUT_DIR}"
cp ".build/apple/Products/Release/rootstock-collector" "../${OUTPUT_DIR}/${BINARY_NAME}"

# Verify
echo ""
echo "Binary: ${OUTPUT_DIR}/${BINARY_NAME}"
echo "Size: $(du -h "../${OUTPUT_DIR}/${BINARY_NAME}" | cut -f1)"
echo "Architectures: $(file "../${OUTPUT_DIR}/${BINARY_NAME}" | grep -o 'arm64\|x86_64' | tr '\n' ' ')"
echo "SHA256: $(shasum -a 256 "../${OUTPUT_DIR}/${BINARY_NAME}" | cut -d' ' -f1)"
echo ""
echo "Verify: ../${OUTPUT_DIR}/${BINARY_NAME} --version"
"../${OUTPUT_DIR}/${BINARY_NAME}" --version
