# Examples

Synthetic fixtures and scripts for Rootstock. These files are the only
assessment-shaped data that belong in the public tree. Real host scans, reports,
viewers, and package inventories stay local and gitignored.

## Included files

### `demo-scan.json`

Synthetic scan data for a fictional Mac named `Acme Corp`. This file is the
example source of truth. After editing it, validate it against the Pydantic
models in `graph/models.py` and the JSON Schema in
`collector/schema/scan-result.schema.json`:

```bash
uv run --project graph --locked python scripts/validate-scan.py examples/demo-scan.json
```

Use this scan to test the graph pipeline without running the collector.

### `cve-scan-export.json`

Synthetic `rootstock-export.json` bridge fixture for graph import of cve-scan
evidence. See [docs/guides/cve-scan-module.md](../docs/guides/cve-scan-module.md).

### `family-export-blue.json` and `family-export-red.json`

Synthetic family open-export fixtures used by the optional rootstock-blue and
rootstock-red → Neo4j import path. See [docs/FAMILY.md](../docs/FAMILY.md) and
`graph/import_family_export.py`.

### `regenerate.sh`

This script validates `demo-scan.json` and rebuilds the pipeline output. It
does not rewrite `demo-scan.json` and requires a running Neo4j instance.

```bash
# Run from the repository root. Start Neo4j if needed.
NEO4J_AUTH=neo4j/CHANGE_ME docker compose -f graph/docker-compose.yml up -d

NEO4J_PASSWORD=CHANGE_ME uv run --project graph --locked \
  bash examples/regenerate.sh
```

This runs schema setup, cached or static CVE enrichment, import, inference,
vulnerability import, classification, and report output. It writes:

- `generated/demo-report.md`: attack-path report
- `generated/demo-graph.json`: OpenGraph JSON for the viewer
- `generated/demo-viewer.html`: offline graph viewer

`generated/` is a local output directory, not the source of truth. Keep demo
data changes in `demo-scan.json`, then regenerate derived outputs.

Environment variables: `NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASSWORD`. The bundled
Neo4j compose file requires `NEO4J_AUTH`, for example `neo4j/CHANGE_ME`.

## Using example data

```bash
# Run these commands from the repository root. The graph commands use the
# locked graph environment.

# Import into Neo4j (one command)
NEO4J_PASSWORD=CHANGE_ME uv run --project graph --locked \
  bash graph/pipeline.sh examples/demo-scan.json

# Or step by step:
NEO4J_PASSWORD=CHANGE_ME uv run --project graph --locked \
  python graph/setup_schema.py
NEO4J_PASSWORD=CHANGE_ME uv run --project graph --locked \
  python graph/import_scan.py --input examples/demo-scan.json
NEO4J_PASSWORD=CHANGE_ME uv run --project graph --locked python graph/infer.py
NEO4J_PASSWORD=CHANGE_ME uv run --project graph --locked \
  python graph/import_vulnerabilities.py
NEO4J_PASSWORD=CHANGE_ME uv run --project graph --locked \
  python graph/tier_classification.py

# Start the API server + interactive viewer
export ROOTSTOCK_API_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
NEO4J_PASSWORD=CHANGE_ME uv run --project graph --locked \
  python graph/server.py --port 8000
# Open http://localhost:8000
```

Install the locked Python environment first with
`uv sync --project graph --locked --all-extras`.
