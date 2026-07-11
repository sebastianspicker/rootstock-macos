#!/usr/bin/env bash
# benchmark.sh — Measure RootstockCLI performance across 3 runs.
#
# Usage:
#   cd collector
#   swift build -c release 2>/dev/null
#   ../scripts/benchmark.sh [binary_path]
#
# Outputs results to stdout and appends a Markdown table to the ignored local
# benchmark record under docs/private/ unless BENCHMARK_OUTPUT is set.

set -euo pipefail

BINARY="${1:-$(dirname "$0")/../collector/.build/release/RootstockCLI}"
OUTFILE_PREFIX="/tmp/rootstock-bench"
BENCHMARK_OUTPUT="${BENCHMARK_OUTPUT:-$(dirname "$0")/../docs/private/benchmark-results.md}"

if [[ ! -x "$BINARY" ]]; then
	echo "ERROR: binary not found or not executable: $BINARY" >&2
	echo "Run 'swift build -c release' in the collector/ directory first." >&2
	exit 1
fi

echo "Binary: $BINARY"
echo "Running 3 benchmark iterations..."
echo ""

declare -a WALLS USERS SYSTEMS SIZES APPS GRANTS

for i in 1 2 3; do
	OUTFILE="${OUTFILE_PREFIX}-${i}.json"

	START=$(date +%s%3N)
	set +e
	/usr/bin/time -l "$BINARY" --output "$OUTFILE" 2>"${OUTFILE_PREFIX}-${i}.time.txt"
	STATUS=$?
	set -e
	END=$(date +%s%3N)

	if [[ "$STATUS" -ne 0 ]]; then
		echo "ERROR: collector run $i failed with exit status $STATUS" >&2
		exit 1
	fi

	WALL=$(echo "scale=2; ($END - $START) / 1000" | bc)
	USER_TIME=$(grep "user" "${OUTFILE_PREFIX}-${i}.time.txt" | awk '{print $1}' | head -1)
	MEM_BYTES=$(grep "maximum resident" "${OUTFILE_PREFIX}-${i}.time.txt" | awk '{print $1}')
	MEM_MB=$(echo "scale=1; $MEM_BYTES / 1048576" | bc)
	SIZE_KB=$(echo "scale=0; $(wc -c <"$OUTFILE") / 1024" | bc)

	if ! COUNTS=$(python3 - "$OUTFILE" <<'PYTHON'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as infile:
    data = json.load(infile)
for key in ("applications", "tcc_grants"):
    if not isinstance(data.get(key), list):
        raise ValueError(f"{key} must be a list")
print(len(data["applications"]), len(data["tcc_grants"]))
PYTHON
	); then
		echo "ERROR: collector run $i produced invalid JSON: $OUTFILE" >&2
		exit 1
	fi
	read -r APP_COUNT GRANT_COUNT <<<"$COUNTS"

	echo "Run $i: ${WALL}s wall, ${MEM_MB} MB peak, ${APP_COUNT} apps, ${GRANT_COUNT} TCC grants, ${SIZE_KB} KB"

	WALLS+=("$WALL")
	USERS+=("${USER_TIME:-?}")
	SYSTEMS+=("?")
	SIZES+=("$SIZE_KB")
	APPS+=("$APP_COUNT")
	GRANTS+=("$GRANT_COUNT")
done

# Compute average wall time
AVG=$(echo "scale=2; (${WALLS[0]} + ${WALLS[1]} + ${WALLS[2]}) / 3" | bc)
AVG_SIZE=$(echo "scale=0; (${SIZES[0]} + ${SIZES[1]} + ${SIZES[2]}) / 3" | bc)

echo ""
echo "Average wall time: ${AVG}s"
echo "Average JSON size: ${AVG_SIZE} KB"

# Per-module verbose timing (one additional run)
echo ""
echo "Per-module timing (verbose run):"
"$BINARY" --output "${OUTFILE_PREFIX}-verbose.json" --verbose 2>&1 | grep -E "^\s+\[|Total:" || true

# Append results to the ignored local benchmark record. Public benchmark docs
# describe the method and targets, not a maintainer's host inventory.
mkdir -p "$(dirname "$BENCHMARK_OUTPUT")"
DATE=$(date -u +"%Y-%m-%d")
HOSTNAME=$(hostname -s)
MACOS=$(sw_vers -productVersion)

{
	echo ""
	echo "## Run on ${DATE} — ${HOSTNAME} (macOS ${MACOS})"
	echo ""
	echo "| Metric | Run 1 | Run 2 | Run 3 | Average |"
	echo "|---|---|---|---|---|"
	echo "| Total time (s)   | ${WALLS[0]} | ${WALLS[1]} | ${WALLS[2]} | ${AVG} |"
	echo "| Apps scanned     | ${APPS[0]} | ${APPS[1]} | ${APPS[2]} | — |"
	echo "| TCC grants       | ${GRANTS[0]} | ${GRANTS[1]} | ${GRANTS[2]} | — |"
	echo "| JSON size (KB)   | ${SIZES[0]} | ${SIZES[1]} | ${SIZES[2]} | ${AVG_SIZE} |"
} >>"$BENCHMARK_OUTPUT"

echo ""
echo "Results appended to $BENCHMARK_OUTPUT"
