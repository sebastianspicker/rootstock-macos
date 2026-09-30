# Explore Rootstock data in Neo4j Browser

This guide walks through starting Neo4j, importing a Rootstock scan, and running
queries over the imported graph in Neo4j Browser with the Rootstock style sheet.

## Prerequisites

- Docker, Neo4j Desktop, or a native Neo4j install
- Python 3 for serving the Browser guide over HTTP
- A Rootstock scan JSON produced by the Swift collector
- Graph dependencies installed with
  `uv sync --project graph --locked --all-extras`

Run the commands in this guide from the repository root unless a command says
otherwise. The graph commands below use the locked Python environment.

## Step 1: Start Neo4j

### Option A: Docker

```bash
export NEO4J_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
NEO4J_AUTH="neo4j/$NEO4J_PASSWORD" \
  docker compose -f graph/docker-compose.yml up -d --wait
```

This generates a password for a new database. Keep it in a private local
configuration. If the data volume already exists, use its existing password.
`--wait` waits for the container health check.

The compose file creates `rootstock-neo4j` and maps ports 7474 and 7687 on
`127.0.0.1`.

### Option B: Neo4j Desktop

1. Download Neo4j Desktop from <https://neo4j.com/download/>.
2. Create a project and add a local database.
3. Set a local password and export the same value as `NEO4J_PASSWORD`.
4. Start the database.

## Step 2: Import a scan

Validate the scan and create the graph constraints before importing:

```sh
uv run --project graph --locked rootstock-graph-validate-scan /path/to/scan.json
uv run --project graph --locked rootstock-graph-setup-schema
uv run --project graph --locked rootstock-graph-import-scan \
  --input /path/to/scan.json --neo4j bolt://localhost:7687
```

The importer reports counts from the selected scan. Review any collection or
import warnings before using those counts as coverage evidence.

Then run relationship inference:

```bash
uv run --project graph --locked rootstock-graph-infer \
  --neo4j bolt://localhost:7687
```

## Step 3: Open Neo4j Browser

Navigate to <http://localhost:7474> and log in with:

- Username: `neo4j`
- Password: the password from `NEO4J_AUTH`

## Step 4: Load the Rootstock Style Sheet

In a second terminal, serve the guide and stylesheet locally:

```bash
python3 -m http.server 8001 --bind 127.0.0.1 --directory graph/browser
```

In the Neo4j Browser query editor, run:

```text
:style http://localhost:8001/rootstock-style.grass
```

After loading the style, applications render blue, TCC permissions render red,
entitlements render amber, and high-risk attack-path edges render thick red.

Run a quick visual check:

```cypher
MATCH (n)-[r]->(m) RETURN n, r, m LIMIT 25
```

## Step 5: Load the Interactive Guide

In the Neo4j Browser query editor, run:

```text
:play http://localhost:8001/rootstock-guide.html
```

The guide panel contains runnable Rootstock query examples.

## Step 6: Save Queries as Favorites

`graph/browser/saved-queries.cypher` contains queries for use in Browser.
The complete packaged query catalog is documented in the
[query reference](../../graph/src/rootstock_graph/resources/queries/README.md). To add a
query to Neo4j Browser Favorites:

1. Copy a query from `saved-queries.cypher`.
2. Paste it into the Neo4j Browser editor.
3. Run it once.
4. Click the star icon in the editor toolbar.
5. Name the favorite.

## Step 7: Generate a Report

After import and inference, generate a Markdown report:

```bash
uv run --project graph --locked rootstock-graph-report \
  --neo4j bolt://localhost:7687 \
  --output rootstock-report.md
```

Add the original scan JSON when richer metadata is needed:

```bash
uv run --project graph --locked rootstock-graph-report \
  --neo4j bolt://localhost:7687 \
  --output rootstock-report.md \
  --scan-json /path/to/scan.json
```

The `rootstock-report.md` basename is ignored by Git. For a real report with a
different name, write it to a private directory outside the checkout.

## Troubleshooting

### Empty graph

```cypher
MATCH (n) RETURN count(n)
```

If the count is `0`, check:

- `rootstock-graph-import-scan` or `graph/pipeline.sh` ran without errors.
- The `--neo4j` URL matches the running instance.
- Port 7687 is reachable: `nc -zv localhost 7687`.

### Style not applied

- Confirm the HTTP server is running:
  `curl http://localhost:8001/rootstock-style.grass | head -5`
- Paste the GraSS content directly through Neo4j Browser settings if the
  `:style` command is blocked.
- Reload the Browser page if Neo4j cached an older style.

### Guide not loading

- Confirm the HTTP server is running:
  `curl http://localhost:8001/rootstock-guide.html | head -5`
- If Browser blocks the local guide, paste queries from
  `graph/browser/saved-queries.cypher` into the query editor.

### Docker cannot connect to Neo4j

```bash
docker compose -f graph/docker-compose.yml ps
docker compose -f graph/docker-compose.yml logs neo4j | tail -20
```

Common causes:

- The container is still starting.
- Another service is using port 7474 or 7687.
- `NEO4J_AUTH` and `NEO4J_PASSWORD` do not match.

### Inference edges not visible

Confirm inference ran successfully:

```cypher
MATCH ()-[r:CAN_INJECT_INTO]->() RETURN count(r) AS injection_edges
```

A zero count may be valid for the loaded evidence. If inference has not run,
run it now and inspect any warnings:

```bash
uv run --project graph --locked rootstock-graph-infer \
  --neo4j bolt://localhost:7687
```
