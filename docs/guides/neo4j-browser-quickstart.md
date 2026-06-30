# Neo4j Browser Quickstart for Rootstock

This guide walks through starting Neo4j, importing a Rootstock scan, and running
interactive attack-path queries in Neo4j Browser with the Rootstock style sheet.

## Prerequisites

- Docker, Neo4j Desktop, or a native Neo4j install
- Python 3 for serving the Browser guide over HTTP
- A Rootstock scan JSON produced by the Swift collector
- Graph dependencies installed with `pip install -r graph/requirements.txt`

## Step 1: Start Neo4j

### Option A: Docker

```bash
cd graph
NEO4J_AUTH=neo4j/CHANGE_ME docker compose up -d
export NEO4J_PASSWORD=CHANGE_ME
```

Wait for Neo4j to start:

```bash
docker compose logs -f neo4j | grep "Started"
```

The compose file creates `rootstock-neo4j` and maps ports 7474 and 7687 on
`127.0.0.1`.

### Option B: Neo4j Desktop

1. Download Neo4j Desktop from <https://neo4j.com/download/>.
2. Create a project and add a local database.
3. Set a local password and export the same value as `NEO4J_PASSWORD`.
4. Start the database.

## Step 2: Import Scan Data

```bash
cd graph
python3 import_scan.py --input /path/to/scan.json --neo4j bolt://localhost:7687
```

Expected shape:

```text
Connected Neo4j bolt://localhost:7687
Importing scan abc-1234 from macbook-pro.local (macOS 14.5)
Imported 247 applications
Imported 89 TCC grants across 22 services
Imported 1,432 entitlements
Imported 12 XPC services
Import complete.
```

Then run relationship inference:

```bash
python3 infer.py --neo4j bolt://localhost:7687
```

## Step 3: Open Neo4j Browser

Navigate to <http://localhost:7474> and log in with:

- **Username:** `neo4j`
- **Password:** the password from `NEO4J_AUTH`

## Step 4: Load the Rootstock Style Sheet

Start the local Browser asset server:

```bash
cd graph/browser
chmod +x setup-browser.sh
./setup-browser.sh
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

`graph/browser/saved-queries.cypher` contains the Rootstock query set. To add a
query to Neo4j Browser Favorites:

1. Copy a query from `saved-queries.cypher`.
2. Paste it into the Neo4j Browser editor.
3. Run it once.
4. Click the star icon in the editor toolbar.
5. Name the favorite.

## Step 7: Generate a Report

After import and inference, generate a Markdown report:

```bash
python3 graph/report.py \
  --neo4j bolt://localhost:7687 \
  --output rootstock-report.md
```

Add the original scan JSON when richer metadata is needed:

```bash
python3 graph/report.py \
  --neo4j bolt://localhost:7687 \
  --output rootstock-report.md \
  --scan-json /path/to/scan.json
```

Generated reports are local artifacts and are ignored by git.

## Troubleshooting

### Empty graph

```cypher
MATCH (n) RETURN count(n)
```

If the count is `0`, check:

- `import_scan.py` ran without errors.
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
- If your Neo4j Browser blocks local HTTP assets, copy the guide HTML into
  `$NEO4J_HOME/import/rootstock-guide.html` and load it with a `file://` URL.

### Docker cannot connect to Neo4j

```bash
docker compose ps
docker compose logs neo4j | tail -20
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

If the count is `0`, re-run:

```bash
python3 graph/infer.py --neo4j bolt://localhost:7687
```
