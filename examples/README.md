# Examples

Demo data and scripts for Rootstock.

## Files

### `demo-scan.json`
Synthetic scan data representing a typical corporate MacBook ("Acme Corp").
This file is the demo source of truth. Edit it directly to add or modify demo data,
then validate it against the Pydantic models in `graph/models.py` and the JSON Schema
in `collector/schema/scan-result.schema.json`:

```bash
python3 scripts/validate-scan.py examples/demo-scan.json
```

Use this scan to test the graph pipeline without running the collector.

### `regenerate.sh`
End-to-end script that validates `demo-scan.json` and rebuilds the pipeline outputs.
It does not rewrite `demo-scan.json`. Requires a running Neo4j instance.

```bash
# Start Neo4j with graph/docker-compose.yml if needed.
cd graph && NEO4J_AUTH=neo4j/CHANGE_ME docker compose up -d && cd ..

NEO4J_PASSWORD=CHANGE_ME bash examples/regenerate.sh
```

This runs the full pipeline (schema, cached/static CVE enrichment, import,
infer, vulnerabilities, classify, report) and produces:
- `generated/demo-report.md` — Full attack path report with Mermaid diagrams and recommendations
- `generated/demo-graph.json` — OpenGraph JSON export for viewer
- `generated/demo-viewer.html` — Interactive Canvas-based graph viewer (open in browser)

`generated/` is a local output directory, not the source of truth. Keep demo
data changes in `demo-scan.json`, then regenerate derived outputs.

Environment variables: `NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASSWORD`. The bundled
Neo4j compose file requires `NEO4J_AUTH`, for example `neo4j/CHANGE_ME`.

## Using Demo Data

```bash
# Import into Neo4j (one command)
NEO4J_PASSWORD=CHANGE_ME bash graph/pipeline.sh examples/demo-scan.json

# Or step by step:
python3 graph/setup_schema.py
python3 graph/import.py --input examples/demo-scan.json
python3 graph/infer.py
python3 graph/import_vulnerabilities.py
python3 graph/tier_classification.py

# Start the API server + interactive viewer
ROOTSTOCK_API_TOKEN=CHANGE_ME_API_TOKEN NEO4J_PASSWORD=CHANGE_ME \
  python3 graph/server.py --port 8000
# Open http://localhost:8000
```

Install Python dependencies first with `pip3 install -r graph/requirements.txt`.
