#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
# Fail if product-facing docs (not research) use forbidden marketing claims.
paths=(README.md docs/architecture.md docs/limitations.md docs/non-goals.md)
forbidden=(
  "bypass TCC"
  "defeat SIP"
  "crack FileVault"
  "replace CrowdStrike"
  "undetectable agent"
)
status=0
for f in "${paths[@]}"; do
  [[ -f "$f" ]] || continue
  for phrase in "${forbidden[@]}"; do
    if grep -qi "$phrase" "$f"; then
      # Allow if the line is clearly documenting prohibition.
      if ! grep -qi "forbidden\|never\|do not\|non-goal\|must not" "$f"; then
        echo "FAIL: '$phrase' in $f"
        status=1
      fi
    fi
  done
done
exit $status
