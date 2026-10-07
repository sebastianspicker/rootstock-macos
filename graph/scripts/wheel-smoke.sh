#!/usr/bin/env bash
# Verify installed console commands and package resources outside the source tree.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GRAPH_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
WHEEL_DIR="$(mktemp -d "${TMPDIR:-/tmp}/rootstock-graph-wheel.XXXXXX")"
VENV_DIR="$(mktemp -d "${TMPDIR:-/tmp}/rootstock-graph-venv.XXXXXX")"

cleanup() {
    rm -rf "$WHEEL_DIR" "$VENV_DIR"
}
trap cleanup EXIT

cd "$GRAPH_DIR"
uv build --wheel --out-dir "$WHEEL_DIR" >/dev/null
WHEEL_PATH="$(find "$WHEEL_DIR" -name 'rootstock_graph-*.whl' -print -quit)"
test -n "$WHEEL_PATH"
"$GRAPH_DIR/.venv/bin/python" -m venv "$VENV_DIR"
uv pip install --python "$VENV_DIR/bin/python" "$WHEEL_PATH" >/dev/null

cd "$WHEEL_DIR"
cp "$GRAPH_DIR/../contracts/family-open-export/v1/fixtures/valid-minimal-red.json" \
    "$WHEEL_DIR/family.json"
cp "$GRAPH_DIR/../contracts/cve-scan-export/v7/fixtures/valid-minimal.json" \
    "$WHEEL_DIR/cve-scan.json"
cp "$GRAPH_DIR/../contracts/collector-scan/fixtures/valid-minimal.json" \
    "$WHEEL_DIR/scan.json"
cat >"$WHEEL_DIR/graph.json" <<'EOF'
{"metadata":{"hostname":"wheel"},"graph":{"nodes":[],"edges":[]}}
EOF

"$VENV_DIR/bin/rootstock-graph-query" --help >/dev/null
"$VENV_DIR/bin/rootstock-graph-viewer" --help >/dev/null
"$VENV_DIR/bin/rootstock-graph-api" --help >/dev/null
"$VENV_DIR/bin/rootstock-graph-report" --help >/dev/null
"$VENV_DIR/bin/rootstock-graph-cve-enrichment" --help >/dev/null
"$VENV_DIR/bin/rootstock-graph-query" --list --no-color >"$WHEEL_DIR/queries.txt"
grep -F "Injectable Full Disk Access Apps" "$WHEEL_DIR/queries.txt" >/dev/null
"$VENV_DIR/bin/rootstock-graph-viewer" \
    --input "$WHEEL_DIR/graph.json" --output "$WHEEL_DIR/viewer.html" >/dev/null
grep -F "RootstockViewer.mount" "$WHEEL_DIR/viewer.html" >/dev/null
"$VENV_DIR/bin/rootstock-graph-import-family-export" \
    --export "$WHEEL_DIR/family.json" --validate-only >/dev/null
"$VENV_DIR/bin/rootstock-graph-import-cve-scan" \
    --input "$WHEEL_DIR/cve-scan.json" --validate-only >/dev/null
"$VENV_DIR/bin/rootstock-graph-validate-scan" "$WHEEL_DIR/scan.json" >"$WHEEL_DIR/validate.txt"
grep -F "Valid: $WHEEL_DIR/scan.json" "$WHEEL_DIR/validate.txt" >/dev/null

echo "installed wheel console/resource smoke passed"
