# Examples

Demo data and scripts for Rootstock.

## Files

### `demo-scan.json`
Synthetic scan data representing a typical corporate MacBook ("Acme Corp"). Contains
15 applications, 15 TCC grants, 5 XPC services, 6 launch items, 4 keychain ACLs,
file ACLs, Bluetooth devices, Kerberos artifacts, and representative entitlements.
Validated against the Pydantic models in `graph/models.py` and the JSON Schema in
`collector/schema/scan-result.schema.json`. Use this to test the graph pipeline
without running the collector.

### `generate_demo_scan.py`
Python script that generates `demo-scan.json`. Edit this to add or modify demo data.

```bash
python3 examples/generate_demo_scan.py
```

### `regenerate.sh`
End-to-end script that regenerates all demo outputs from `demo-scan.json`.
Requires a running Neo4j instance.

```bash
# Ensure Neo4j is running, then:
bash examples/regenerate.sh
```

This runs the full pipeline (schema, CVE enrichment, import, infer, vulnerabilities,
classify, report) and produces:
- `generated/demo-report.md` — Full attack path report with Mermaid diagrams and recommendations
- `generated/demo-graph.json` — OpenGraph JSON export for viewer
- `generated/demo-viewer.html` — Interactive Canvas-based graph viewer (open in browser)

Environment variables: `NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASSWORD`.

## Using Demo Data

```bash
# Import into Neo4j (one command)
bash graph/pipeline.sh examples/demo-scan.json

# Or step by step:
python3 graph/setup_schema.py
python3 graph/import.py --input examples/demo-scan.json
python3 graph/infer.py
python3 graph/import_vulnerabilities.py
python3 graph/tier_classification.py

# Start the API server + interactive viewer
python3 graph/server.py --port 8000
# Open http://localhost:8000
```

Install Python dependencies first with `pip3 install -r graph/requirements.txt`.
