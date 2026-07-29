#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
OUT="${1:-Fixtures/cases/sample.rsbcase}"
rm -rf "$OUT"
swift run rootstock-blue case create "$OUT" --name sample
swift run rootstock-blue case verify "$OUT"
echo "wrote $OUT"
