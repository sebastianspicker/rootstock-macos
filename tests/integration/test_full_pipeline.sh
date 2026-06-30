#!/usr/bin/env bash
# test_full_pipeline.sh — Rootstock end-to-end smoke test.

set -euo pipefail

NEO4J_URI="${NEO4J_URI:-bolt://localhost:7687}"
NEO4J_USER="${NEO4J_USER:-neo4j}"
NEO4J_PASSWORD="${NEO4J_PASSWORD:-}"
NEO4J_AUTH="${NEO4J_AUTH:-}"

if [[ -z "$NEO4J_PASSWORD" && "$NEO4J_AUTH" != "none" ]]; then
	echo "ERROR: Set NEO4J_PASSWORD before running the integration test" >&2
	exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GRAPH_DIR="$REPO_ROOT/graph"
FIXTURE_JSON="$GRAPH_DIR/tests/fixture_minimal.json"
REPORT_OUT="/tmp/rootstock-integration-report.md"
REPORT_ERR="/tmp/rootstock-integration-report.err"
TEMP_SCAN_JSON="/tmp/rootstock-integration-scan.json"
TEST_SCAN_ID="integration-$(date +%s)"

PASS=0
FAIL=0

ok() {
	echo "  PASS: $1"
	PASS=$((PASS + 1))
}
fail() {
	echo "  FAIL: $1"
	FAIL=$((FAIL + 1))
}
step() {
	echo
	echo "== $1 =="
}

run_count() {
	python3 - "$1" <<'PYTHON'
import os
import sys
from neo4j import GraphDatabase

query = sys.argv[1]
driver = GraphDatabase.driver(
    os.environ["NEO4J_URI"],
    auth=None if os.environ.get("NEO4J_AUTH") == "none" else (
        os.environ["NEO4J_USER"],
        os.environ["NEO4J_PASSWORD"],
    ),
)
with driver.session() as session:
    record = session.run(query).single()
    print(record[0] if record else 0)
driver.close()
PYTHON
}

cleanup() {
	rm -f "$TEMP_SCAN_JSON" "$REPORT_OUT" "$REPORT_ERR"
	python3 - <<'PYTHON'
import os
from neo4j import GraphDatabase

scan_id = os.environ["TEST_SCAN_ID"]
driver = GraphDatabase.driver(
    os.environ["NEO4J_URI"],
    auth=None if os.environ.get("NEO4J_AUTH") == "none" else (
        os.environ["NEO4J_USER"],
        os.environ["NEO4J_PASSWORD"],
    ),
)
with driver.session() as session:
    session.run(
        "MATCH (n) WHERE n.scan_id = $scan_id DETACH DELETE n",
        scan_id=scan_id,
    )
driver.close()
PYTHON
}

export NEO4J_URI NEO4J_USER NEO4J_PASSWORD NEO4J_AUTH TEST_SCAN_ID FIXTURE_JSON TEMP_SCAN_JSON

trap cleanup EXIT

step "Pre-flight"

if [[ ! -f "$FIXTURE_JSON" ]]; then
	echo "ERROR: Fixture JSON not found at $FIXTURE_JSON" >&2
	exit 1
fi
ok "fixture JSON found"

python3 - <<'PYTHON'
import json
import os

with open(os.environ["FIXTURE_JSON"]) as infile:
    data = json.load(infile)

data["scan_id"] = os.environ["TEST_SCAN_ID"]

with open(os.environ["TEMP_SCAN_JSON"], "w") as outfile:
    json.dump(data, outfile)
PYTHON
ok "temporary integration scan written"

python3 - <<'PYTHON' >/dev/null
import os
from neo4j import GraphDatabase

driver = GraphDatabase.driver(
    os.environ["NEO4J_URI"],
    auth=None if os.environ.get("NEO4J_AUTH") == "none" else (
        os.environ["NEO4J_USER"],
        os.environ["NEO4J_PASSWORD"],
    ),
)
driver.verify_connectivity()
driver.close()
PYTHON
ok "Neo4j reachable"

step "Schema"
python3 "$GRAPH_DIR/setup_schema.py" >/dev/null
ok "schema applied"

step "Import"
python3 "$GRAPH_DIR/import_scan.py" --input "$TEMP_SCAN_JSON" >/dev/null

APP_COUNT="$(run_count "MATCH (a:Application {scan_id: '$TEST_SCAN_ID'}) RETURN count(a)")"
if [[ "$APP_COUNT" -ge 3 ]]; then
	ok "applications imported ($APP_COUNT)"
else
	fail "expected >=3 applications, got $APP_COUNT"
fi

TCC_COUNT="$(run_count "MATCH (:Application {scan_id: '$TEST_SCAN_ID'})-[r:HAS_TCC_GRANT]->() RETURN count(r)")"
if [[ "$TCC_COUNT" -ge 1 ]]; then
	ok "TCC grant edges imported ($TCC_COUNT)"
else
	fail "expected TCC grant edges after import"
fi

step "Inference"
python3 "$GRAPH_DIR/infer.py" >/dev/null

INJECT_COUNT="$(run_count "MATCH ()-[r:CAN_INJECT_INTO {inferred: true}]->(:Application {scan_id: '$TEST_SCAN_ID'}) RETURN count(r)")"
if [[ "$INJECT_COUNT" -ge 1 ]]; then
	ok "inference created CAN_INJECT_INTO edges ($INJECT_COUNT)"
else
	fail "expected CAN_INJECT_INTO edges after inference"
fi

step "Report Surface"
if python3 "$GRAPH_DIR/report.py" --output "$REPORT_OUT" --scan-json "$TEMP_SCAN_JSON" >/dev/null 2>"$REPORT_ERR"; then
	ok "report command completed"
else
	fail "report command failed"
	if [[ -s "$REPORT_ERR" ]]; then
		sed 's/^/  report stderr: /' "$REPORT_ERR" >&2
	fi
fi

if [[ -s "$REPORT_OUT" ]]; then
	ok "report generated"
else
	fail "report output missing"
fi

if grep -Eq "Query failed|Metadata query failed|Traceback|✗" "$REPORT_ERR"; then
	fail "report command emitted query or metadata failure"
else
	ok "report command emitted no query or metadata failures"
fi

if grep -q "# Rootstock Security Assessment Report" "$REPORT_OUT" \
	&& grep -q "## Scan Metadata" "$REPORT_OUT" \
	&& grep -q "## Executive Summary" "$REPORT_OUT" \
	&& grep -q "$TEST_SCAN_ID" "$REPORT_OUT"; then
	ok "report contains expected semantic sections and scan id"
else
	fail "report missing expected semantic sections or scan id"
fi

echo
echo "Integration test results: $PASS passed, $FAIL failed"

if [[ "$FAIL" -gt 0 ]]; then
	exit 1
fi
