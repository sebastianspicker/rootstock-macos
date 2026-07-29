#!/usr/bin/env bash
# Build the default assess-only rootstock-red product.
set -euo pipefail
cd "$(dirname "$0")/.."
swift build -c release --product rootstock-red
echo "Built: $(swift build -c release --show-bin-path)/rootstock-red"
