#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
# Fail if product-facing docs (not research) use forbidden marketing claims.
# The phrase list is read from NonGoals.messagingForbidden so the check and the
# product constant cannot drift apart.
paths=(README.md docs/architecture.md docs/limitations.md docs/non-goals.md)
source_file=Sources/RootstockBlueCore/NonGoals.swift

forbidden=()
while IFS= read -r phrase; do
  forbidden+=("$phrase")
done < <(
  sed -n '/messagingForbidden: \[String\] = \[/,/^[[:space:]]*\]/p' "$source_file" |
    sed -n 's/^[[:space:]]*"\(.*\)",\{0,1\}[[:space:]]*$/\1/p'
)
if [[ ${#forbidden[@]} -eq 0 ]]; then
  echo "FAIL: no messagingForbidden phrases found in $source_file" >&2
  exit 1
fi

status=0
for f in "${paths[@]}"; do
  [[ -f "$f" ]] || continue
  for phrase in "${forbidden[@]}"; do
    while IFS= read -r match; do
      # Allow only a line that itself documents the prohibition.
      if ! grep -qiE "forbidden|never|do not|non-goal|must not" <<<"$match"; then
        echo "FAIL: '$phrase' in $f:$match"
        status=1
      fi
    done < <(grep -niF -- "$phrase" "$f" || true)
  done
done
exit $status
