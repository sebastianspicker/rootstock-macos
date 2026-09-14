# Examples

This directory contains Rootstock's synthetic fixtures and example scripts.
Only synthetic assessment data belongs in the public repository. Store real
host scans, reports, viewers, and package inventories in a private directory
outside the checkout.

## Included files

### `demo-scan.json`

This maintained example describes the fictional host `acme-macbook-pro` with
placeholder Acme Corp identifiers. After editing it, validate it against the
Pydantic models in `graph/src/rootstock_graph/models.py` and the canonical JSON
Schema in `contracts/collector-scan/legacy-unversioned.schema.json`:

```bash
uv run --project graph --locked python scripts/validate-scan.py examples/demo-scan.json
```

Use this scan to test the graph pipeline without running the collector.

### `cve-scan-export.json`

This synthetic `rootstock-export.json` fixture demonstrates the version 7 CVE
graph export. See the [cve-scan README](../modules/cve-scan/README.md) and
[product-family map](../docs/FAMILY.md).

### `family-export-blue.json` and `family-export-red.json`

These synthetic family open exports exercise the optional Red and Blue import
path into Neo4j. See the [product-family map](../docs/FAMILY.md) and the
`rootstock-graph-import-family-export` command.

### `regenerate.sh`

This script validates `demo-scan.json` and rebuilds the derived pipeline
output. It leaves `demo-scan.json` unchanged and requires a running Neo4j
instance.

```bash
# Run from the repository root. Start Neo4j if needed.
NEO4J_AUTH=neo4j/CHANGE_ME docker compose -f graph/docker-compose.yml up -d

NEO4J_PASSWORD=CHANGE_ME uv run --project graph --locked \
  bash examples/regenerate.sh
```

The script sets up the graph schema, performs cached or static CVE enrichment,
imports the scan and vulnerability data, runs inference and classification,
and writes:

- `generated/demo-report.md`: attack-path report
- `generated/demo-graph.json`: OpenGraph JSON for the viewer
- `generated/demo-viewer.html`: offline graph viewer

`generated/` contains local derived output. Make lasting fixture changes in
`demo-scan.json`, then regenerate this directory.

Graph import commands use `NEO4J_URI`, `NEO4J_USER`, and `NEO4J_PASSWORD`.
The API also requires a separate read-only `NEO4J_READ_USER` and its
`NEO4J_READ_PASSWORD`; see [configuration](../docs/CONFIGURATION.md) for the
required Neo4j privileges. The bundled Neo4j compose file requires
`NEO4J_AUTH`, for example `neo4j/CHANGE_ME`.

## Using example data

```bash
# Run these commands from the repository root. The graph commands use the
# locked graph environment.

# Import into Neo4j (one command)
NEO4J_PASSWORD=CHANGE_ME uv run --project graph --locked \
  bash graph/pipeline.sh examples/demo-scan.json

# Or step by step:
NEO4J_PASSWORD=CHANGE_ME uv run --project graph --locked \
  rootstock-graph-setup-schema
NEO4J_PASSWORD=CHANGE_ME uv run --project graph --locked \
  rootstock-graph-import-scan --input examples/demo-scan.json
NEO4J_PASSWORD=CHANGE_ME uv run --project graph --locked rootstock-graph-infer
NEO4J_PASSWORD=CHANGE_ME uv run --project graph --locked \
  rootstock-graph-import-vulnerabilities
NEO4J_PASSWORD=CHANGE_ME uv run --project graph --locked \
  rootstock-graph-tier-classification

# Start the API server + interactive viewer
export ROOTSTOCK_API_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
export NEO4J_READ_USER=rootstock_api_read
export NEO4J_READ_PASSWORD=CHANGE_ME
NEO4J_PASSWORD=CHANGE_ME uv run --project graph --locked \
  rootstock-graph-api --port 8000
# Open http://localhost:8000
```

Install the locked Python environment first with
`uv sync --project graph --locked --all-extras`.
