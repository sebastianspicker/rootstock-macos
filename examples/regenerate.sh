#!/usr/bin/env bash
#
# regenerate.sh — Rebuild all demo outputs from scratch.
#
# Requires a running Neo4j instance (default: bolt://localhost:7687).
# The repository only commits demo-scan.json. Regenerated report/viewer artifacts
# are written under examples/generated/.
#
# Usage:
#   bash examples/regenerate.sh
#   bash examples/regenerate.sh --neo4j bolt://host:7687 --username neo4j --password secret

set -euo pipefail
cd "$(dirname "$0")/.."

OUTPUT_DIR="examples/generated"
mkdir -p "$OUTPUT_DIR"

# Parse optional Neo4j args (env vars override defaults, CLI args override env vars)
NEO4J_URI="${NEO4J_URI:-bolt://localhost:7687}"
NEO4J_USER="${NEO4J_USER:-neo4j}"
NEO4J_PASS="${NEO4J_PASSWORD:-rootstock}"

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
	*)
		echo "Unknown option: $1"
		exit 1
		;;
	esac
done

NEO4J_ARGS=(--neo4j "$NEO4J_URI" --neo4j-user "$NEO4J_USER" --neo4j-password "$NEO4J_PASS")

# Check Neo4j connectivity
echo "==> Checking Neo4j at $NEO4J_URI ..."
python3 -c "
from neo4j import GraphDatabase
d = GraphDatabase.driver('$NEO4J_URI', auth=('$NEO4J_USER', '$NEO4J_PASS'))
d.verify_connectivity()
d.close()
print('  Neo4j OK')
" || {
	echo "ERROR: Cannot connect to Neo4j at $NEO4J_URI"
	exit 1
}

# 1. Generate synthetic scan JSON
echo "==> Generating demo-scan.json ..."
python3 examples/generate_demo_scan.py -o examples/demo-scan.json

# 2. Run full pipeline (schema → import → infer → classify)
echo "==> Running pipeline ..."
bash graph/pipeline.sh examples/demo-scan.json \
	--neo4j "$NEO4J_URI" --username "$NEO4J_USER" --password "$NEO4J_PASS" \
	--report "$OUTPUT_DIR/demo-report.md"

# 3. Export OpenGraph JSON
echo "==> Exporting graph JSON ..."
python3 graph/opengraph_export.py "${NEO4J_ARGS[@]}" -o "$OUTPUT_DIR/demo-graph.json"

# 4. Generate self-contained HTML viewer
echo "==> Generating viewer HTML ..."
python3 graph/viewer.py -i "$OUTPUT_DIR/demo-graph.json" -o "$OUTPUT_DIR/demo-viewer.html"

echo ""
echo "Done! Generated:"
echo "  examples/demo-scan.json              — synthetic scan data"
echo "  examples/generated/demo-report.md    — attack path report"
echo "  examples/generated/demo-graph.json   — graph export for viewer"
echo "  examples/generated/demo-viewer.html  — interactive graph viewer"
