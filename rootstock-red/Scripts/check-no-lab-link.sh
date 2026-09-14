#!/usr/bin/env bash
# Ensure default rootstock-red binary does not contain RootstockLab symbols.
set -euo pipefail
cd "$(dirname "$0")/.."
BIN="$(swift build -c debug -Xswiftc -warnings-as-errors --show-bin-path)/rootstock-red"
if [[ ! -x "$BIN" ]]; then
  swift build -c debug --product rootstock-red -Xswiftc -warnings-as-errors
  BIN="$(swift build -c debug -Xswiftc -warnings-as-errors --show-bin-path)/rootstock-red"
fi
if nm -gU "$BIN" 2>/dev/null | grep -E 'RootstockLab' >/dev/null; then
  echo "FAIL: lab symbols found in assess binary" >&2
  exit 1
fi
echo "OK: no lab global symbols detected in $BIN"
