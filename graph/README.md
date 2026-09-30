# rootstock-graph

`rootstock-graph` is Rootstock Core's Python analysis package. It validates and
imports collector, family, and CVE artifacts into Neo4j; derives modeled
relationships; and provides queries, reports, exports, a local API, and offline
or live viewers.

## Requirements and setup

- Python 3.10 or later; use Python 3.11 for CI parity
- `uv`
- Neo4j 5.x for import, inference, query, report, and live API workflows

From the repository root:

```sh
uv sync --project graph --locked --all-extras
(cd graph && NEO4J_AUTH=neo4j/CHANGE_ME docker compose up -d)
```

Replace `CHANGE_ME` with a generated local password. The bundled Compose
service publishes Browser and Bolt only on loopback and stores data and logs in
named Docker volumes.

## Package and command boundaries

The implementation lives in `src/rootstock_graph/`:

- `ingestion/` validates and imports collector, family, CVE, and SharpHound
  artifacts.
- `inference/` derives relationships, ownership, risk, recommendations, and
  tiers.
- `reporting/` contains packaged queries, reports, diffs, OpenGraph exports,
  and viewers.
- `vulnerability/` contains the curated reference catalog, enrichment, and
  version matching.
- `api_support/` holds the API routes (an `APIRouter`), schemas, dependencies,
  and report helpers; `api.py` is the ASGI app that includes them.
- `category_predicates.py`, `constants.py`, `cypher.py`, `models.py`,
  `neo4j.py`, `paths.py`, and `server_validation.py` are foundation modules
  that every layer may use.

Layers depend downward only: foundation, `vulnerability`, `ingestion`,
`reporting`, `api_support`, `api`; `inference` sits on foundation and feeds
`api_support`. `tests/test_architecture.py` enforces this, forbids cross-module
private imports, and rejects dynamic imports.

Use the `rootstock-graph-*` console commands declared in `pyproject.toml`.
There are no supported root-level Python command wrappers.

## Core workflow

Run the complete Core pipeline from the repository root:

```sh
NEO4J_PASSWORD=CHANGE_ME bash graph/pipeline.sh examples/demo-scan.json
```

The pipeline requires a collector scan as its positional input. An optional
cve-scan export is additive:

```sh
NEO4J_PASSWORD=CHANGE_ME bash graph/pipeline.sh examples/demo-scan.json \
  --cve-scan-export examples/cve-scan-export.json
```

Individual installed commands are also available:

```sh
NEO4J_PASSWORD=CHANGE_ME uv run --project graph --locked \
  rootstock-graph-import-scan --input examples/demo-scan.json
NEO4J_PASSWORD=CHANGE_ME uv run --project graph --locked rootstock-graph-infer
NEO4J_PASSWORD=CHANGE_ME uv run --project graph --locked \
  rootstock-graph-report --output /tmp/rootstock-report.md \
  --scan-json examples/demo-scan.json
```

Use `rootstock-graph-query --list` for the packaged query catalog. The packaged
[query guide](src/rootstock_graph/resources/queries/README.md) explains result
interpretation without duplicating the CLI-generated list.

## API and viewer

Start the API only after setting a token of at least 32 bytes and separate
Neo4j writer and read-principal credentials:

```sh
export ROOTSTOCK_API_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
export NEO4J_READ_USER=rootstock_graph_read
export NEO4J_READ_PASSWORD=CHANGE_ME_READ
NEO4J_PASSWORD=CHANGE_ME_WRITE uv run --project graph --locked \
  rootstock-graph-api --port 8000
```

The API and its Neo4j URI are loopback-only. One bearer token protects every
`/api/*` route. Read routes use the separate `NEO4J_READ_*` principal; ad-hoc
Cypher is read-only and bounded. Authenticated owned-marker and
tier-classification endpoints retain the writer principal because they
intentionally update derived graph state. Grant the read principal only
`MATCH` and `SHOW` privileges, with no `WRITE` or `DBMS` privileges. Do not
proxy or tunnel this alpha service for real data.

Viewer TypeScript and CSS are authored in `graph/viewer/src/` and
`graph/viewer/css/`. Run `npm run bundle` in `graph/viewer` to rebuild the
packaged assets in `src/rootstock_graph/resources/viewer/`; do not edit those
generated assets by hand. Static viewers embed graph data, while the live viewer retrieves it from
the authenticated API.

The viewer opens with Scope, Evidence, and Report steps. Its Graph step includes
triage, graph, path, and query workspaces. Offline reports summarize the
embedded snapshot. Live reports use the assessment generator through
authenticated `POST /api/report`, which accepts only `{"format":"markdown"}`
or `{"format":"html"}`. The route uses the read principal, packaged read-only
queries, a 12-second total query budget, and a five-second timeout per query.
It rejects results above 1,000 rows per query, 20,000 rows total, or 8 MiB of
rendered output. Reports cover the loaded graph, not only the selected app, and
retain collection-coverage caveats. Files download through the browser; the API
does not accept filesystem destinations.

Interactive graph exports use parameterized database limits and five-second
query timeouts. If the node limit is exceeded, the API returns an oversize
response before fetching relationships. Endpoint queries include identity
properties with the relationship evidence. CLI exports have no default size
limit.

## Reference documentation

- The [packaged query guide](src/rootstock_graph/resources/queries/README.md)
  explains how to run and interpret the query catalog.
- The [packaged contract mirror note](src/rootstock_graph/resources/contracts/README.md)
  explains which schemas are copied into the installed package.
- The [Neo4j Browser guide source](browser/rootstock-guide.html) is served by
  `graph/browser/setup-browser.sh` for use inside Neo4j Browser.

## Packaging and verification

The files under `src/rootstock_graph/resources/contracts/` (for example
`family-open-export/v1/schema.json`) are read-only installation copies of
canonical repository contracts. `scripts/check-contracts.py`
requires every mirror to be byte-for-byte identical to its canonical file.

Run from the repository root:

```sh
sh scripts/verify graph
sh scripts/verify web
```

The graph lane runs Ruff, the graph test suite, contract and scan-model checks,
synthetic scan validation with `rootstock-graph-validate-scan`, and an isolated
wheel smoke test. The web lane needs `npm ci --ignore-scripts` in
`graph/viewer`; it type-checks, lints, and tests the viewer, then compares a temporary build with the
packaged assets in the working tree. Run `npm run bundle` in `graph/viewer` to
refresh those assets. Test a live Neo4j connection and API separately:

```sh
NEO4J_PASSWORD=CHANGE_ME_WRITE \
NEO4J_READ_USER=rootstock_graph_read \
NEO4J_READ_PASSWORD=CHANGE_ME_READ \
  sh scripts/verify neo4j
```

Configuration, secrets, trusted inputs, and output handling are documented in
[`docs/CONFIGURATION.md`](../docs/CONFIGURATION.md). Real database contents,
reports, viewers, tokens, and query history are confidential local artifacts.
