#!/usr/bin/env bash
#
# regenerate.sh - Rebuild demo outputs from the checked-in demo scan.
#
# Requires a running Neo4j instance (default: bolt://localhost:7687).
# The repository commits demo-scan.json as the demo source of truth. Pipeline artifacts
# are written under examples/generated/.
#
# Usage:
#   bash examples/regenerate.sh
#   NEO4J_PASSWORD=secret bash examples/regenerate.sh --neo4j bolt://host:7687 --username neo4j
#   NEO4J_PASSWORD=secret bash examples/regenerate.sh --cve-scan-export examples/cve-scan-export.json

set -euo pipefail
cd "$(dirname "$0")/.."

OUTPUT_DIR="examples/generated"
mkdir -p "$OUTPUT_DIR"
DEFAULT_CVE_SCAN_EXPORT="examples/cve-scan-export.json"

# Parse optional Neo4j args (env vars override defaults, CLI args override env vars)
NEO4J_URI="${NEO4J_URI:-bolt://localhost:7687}"
NEO4J_USER="${NEO4J_USER:-neo4j}"
NEO4J_PASS="${NEO4J_PASSWORD:-}"
CVE_SCAN_EXPORT="$DEFAULT_CVE_SCAN_EXPORT"
CVE_SCAN_EXPORT_REQUESTED=false
SKIP_CVE_SCAN_EXPORT=false

while [[ $# -gt 0 ]]; do
	case "$1" in
	--neo4j)
		NEO4J_URI="$2"
		shift 2
		;;
	--username)
		NEO4J_USER="$2"
		shift 2
		;;
	--password)
		NEO4J_PASS="$2"
		shift 2
		;;
	--cve-scan-export)
		CVE_SCAN_EXPORT="$2"
		CVE_SCAN_EXPORT_REQUESTED=true
		shift 2
		;;
	--skip-cve-scan-export)
		SKIP_CVE_SCAN_EXPORT=true
		shift
		;;
	*)
		echo "Unknown option: $1"
		exit 1
		;;
esac
done

if [[ -z "$NEO4J_PASS" ]]; then
	echo "ERROR: Set NEO4J_PASSWORD or pass --password" >&2
	exit 1
fi

CVE_SCAN_ARGS=()
if [[ "$SKIP_CVE_SCAN_EXPORT" = false ]]; then
	if [[ -f "$CVE_SCAN_EXPORT" ]]; then
		CVE_SCAN_ARGS=(--cve-scan-export "$CVE_SCAN_EXPORT")
	elif [[ "$CVE_SCAN_EXPORT_REQUESTED" = true ]]; then
		echo "ERROR: cve-scan export not found: $CVE_SCAN_EXPORT" >&2
		exit 1
	fi
fi

export NEO4J_URI NEO4J_USER
export NEO4J_PASSWORD="$NEO4J_PASS"
NEO4J_ARGS=(--neo4j "$NEO4J_URI" --neo4j-user "$NEO4J_USER")

# Check Neo4j connectivity
echo "==> Checking Neo4j at $NEO4J_URI ..."
python3 - <<'PY' || {
import os
from neo4j import GraphDatabase
d = GraphDatabase.driver(
    os.environ['NEO4J_URI'],
    auth=(os.environ['NEO4J_USER'], os.environ['NEO4J_PASSWORD']),
)
d.verify_connectivity()
d.close()
print('  Neo4j OK')
PY
	echo "ERROR: Cannot connect to Neo4j at $NEO4J_URI"
	exit 1
}

# 1. Validate checked-in synthetic scan JSON
echo "==> Validating demo-scan.json ..."
python3 scripts/validate-scan.py examples/demo-scan.json

# 2. Run full pipeline (schema → import → infer → classify)
echo "==> Running pipeline ..."
bash graph/pipeline.sh examples/demo-scan.json \
	--neo4j "$NEO4J_URI" --username "$NEO4J_USER" \
	--report "$OUTPUT_DIR/demo-report.md" \
	"${CVE_SCAN_ARGS[@]}"

# 3. Export OpenGraph JSON
echo "==> Exporting graph JSON ..."
python3 graph/opengraph_export.py "${NEO4J_ARGS[@]}" -o "$OUTPUT_DIR/demo-graph.json"

# 4. Generate self-contained HTML viewer
echo "==> Generating viewer HTML ..."
python3 graph/viewer.py -i "$OUTPUT_DIR/demo-graph.json" -o "$OUTPUT_DIR/demo-viewer.html"

echo ""
echo "Done! Generated:"
echo "  examples/demo-scan.json - validated synthetic scan data"
if [[ "${#CVE_SCAN_ARGS[@]}" -gt 0 ]]; then
	echo "  $CVE_SCAN_EXPORT - imported cve-scan graph fixture"
fi
echo "  examples/generated/demo-report.md - attack path report"
echo "  examples/generated/demo-graph.json - graph export for viewer"
echo "  examples/generated/demo-viewer.html - interactive graph viewer"
