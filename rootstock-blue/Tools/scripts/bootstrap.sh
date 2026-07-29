#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
echo "RootstockBlue bootstrap"
command -v swift >/dev/null || { echo "swift not found"; exit 1; }
swift --version
swift package resolve
echo "OK - run: make test"
