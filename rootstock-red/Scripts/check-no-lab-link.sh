#!/usr/bin/env bash
# Ensure default rootstock-red binary does not contain RootstockLab / MacAgentKit symbols.
set -euo pipefail
cd "$(dirname "$0")/.."
BIN="$(swift build -c debug --show-bin-path)/rootstock-red"
if [[ ! -x "$BIN" ]]; then
  swift build -c debug --product rootstock-red
  BIN="$(swift build -c debug --show-bin-path)/rootstock-red"
fi
if nm -gU "$BIN" 2>/dev/null | grep -E 'RootstockLab|MacAgentKit|MacTransportKit' >/dev/null; then
  echo "FAIL: lab/agent/transport symbols found in assess binary" >&2
  exit 1
fi
echo "OK: no lab/agent/transport global symbols detected in $BIN"
