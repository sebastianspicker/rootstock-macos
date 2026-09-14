#!/usr/bin/env bash
# Build the default assess-only rootstock-red product.
set -euo pipefail
cd "$(dirname "$0")/.."
swift build -c release --product rootstock-red -Xswiftc -warnings-as-errors
echo "Built: $(swift build -c release -Xswiftc -warnings-as-errors --show-bin-path)/rootstock-red"
