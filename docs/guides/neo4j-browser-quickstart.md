# Neo4j Browser Quickstart — Rootstock

This guide covers the complete workflow from starting Neo4j to running
interactive attack-path queries in Neo4j Browser with the Rootstock style sheet.

---

## Prerequisites

- Docker (recommended) or Neo4j Desktop / native install
- Python 3 (for serving the Browser Guide over HTTP)
- A completed Rootstock scan: `scan.json` produced by the Swift collector
- `graph/requirements.txt` dependencies installed: `pip install -r graph/requirements.txt`

---

## Step 1: Start Neo4j

### Option A: Docker (recommended)

```bash
cd graph
docker compose up -d
```

Wait for Neo4j to be ready (about 30 seconds):

```bash
docker compose logs -f neo4j | grep "Started"
# Expected: INFO  Started.
```

**What this looks like:** Docker pulls the `neo4j:5.26` image (first run only),
creates a container named `rootstock-neo4j`, and maps ports 7474 (HTTP) and 7687 (Bolt).

### Option B: Neo4j Desktop

1. Download from https://neo4j.com/download/
2. Create a new project, add a local database
3. Set the password to `rootstock` (or configure `NEO4J_AUTH` in your environment)
4. Start the database

---

## Step 2: Import Scan Data

```bash
cd graph
python3 import.py --input /path/to/scan.json --neo4j bolt://localhost:7687
```

**Expected output:**
```
Connected to Neo4j bolt://localhost:7687
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

**Expected output:**
```
Inferring CAN_INJECT_INTO relationships…  34 edges created
Inferring CHILD_INHERITS_TCC relationships…  7 edges created
Inferring CAN_SEND_APPLE_EVENT relationships…  12 edges created
Inference complete.
```

**What this looks like:** Neo4j Browser's relationship count in the schema
diagram (☁ icon, top-left) should show Application, TCC_Permission, Entitlement,
and relationship type counts matching the import output.

---

## Step 3: Open Neo4j Browser

Navigate to: **http://localhost:7474**

Log in with:
- **Username:** `neo4j`
- **Password:** `rootstock` (or whatever you set in `NEO4J_AUTH`)

**What this looks like:** The Neo4j Browser home screen shows a query editor at the
top, a sidebar with Favorites and Database info on the left, and a graph canvas
in the centre.

---

## Step 4: Load the Rootstock Style Sheet

The GraSS (Graph Style Sheet) assigns distinct colours to each node type,
making it easy to visually distinguish Applications (blue), TCC permissions (red),
entitlements (amber), and attack paths (thick red edges).

### 4a: Start the local HTTP server

In a separate terminal:

```bash
cd graph/browser
chmod +x setup-browser.sh
./setup-browser.sh
```

The script starts a Python HTTP server on port 8001 and prints setup instructions.

### 4b: Apply the style in Neo4j Browser

In the Neo4j Browser query editor, run:

```
:style http://localhost:8001/rootstock-style.grass
```

Click **Yes** when prompted to replace the current style.

**What this looks like:** After loading the style, nodes in the graph canvas
immediately change colour:
- Application nodes turn **blue**
- TCC_Permission nodes turn **red**
- Entitlement nodes turn **amber/yellow**
- CAN_INJECT_INTO edges appear **thick red**

Run a quick test to confirm:

```cypher
MATCH (n)-[r]->(m) RETURN n, r, m LIMIT 25
```

---

## Step 5: Load the Interactive Guide

In the Neo4j Browser query editor, run:

```
:play http://localhost:8001/rootstock-guide.html
```

**What this looks like:** A panel slides up from the bottom of the screen
with the Rootstock guide. It contains 7 slides navigable with ← → arrows.
Each slide has a runnable Cypher query — click the query block to copy it
into the editor, then click the play button (▶) to run it.

### Guide Slides

| Slide | Topic |
|-------|-------|
| 1 | Welcome to Rootstock — graph overview |
| 2 | Getting Started — explore all TCC grants |
| 3 | Find Injectable Apps — Killer Query 1 |
| 4 | Attack Paths — shortestPath to FDA |
| 5 | Electron Risks — TCC inheritance |
| 6 | Blue Team Audit — TCC overview |
| 7 | Next Steps — query library and report generation |

---

## Step 6: Save Queries to Favorites

The file `graph/browser/saved-queries.cypher` contains all 10 Killer Queries
plus 5 exploratory queries with descriptive comments.

To add them to Neo4j Browser's Favorites sidebar:

1. Copy a query from `saved-queries.cypher`
2. Paste it into the Neo4j Browser editor
3. Run it once
4. Click the **star icon (☆)** in the editor toolbar
5. Enter a name when prompted (e.g., "Injectable FDA Apps")

Repeat for each query. Your Favorites appear in the left sidebar under ☆.

---

## Step 7: Generate a Security Report

Once data is imported and inference has run, generate a full Markdown report:

```bash
python3 graph/report.py \
  --neo4j bolt://localhost:7687 \
  --output rootstock-report.md

# Or with original scan JSON for richer metadata:
python3 graph/report.py \
  --neo4j bolt://localhost:7687 \
  --output rootstock-report.md \
  --scan-json /path/to/scan.json
```

**Expected output:**
```
Connecting to Neo4j at bolt://localhost:7687…
  Connected.
Running queries…
  ✓ 01-injectable-fda-apps.cypher: 3 rows
  ✓ 02-shortest-path-to-fda.cypher: 5 rows
  ✓ 03-electron-tcc-inheritance.cypher: 2 rows
  ...
Assembling report…
Report written to rootstock-report.md
```

---

## Troubleshooting

### Empty graph (no nodes returned)

```
MATCH (n) RETURN count(n)
```

If this returns `0`, the import did not complete. Check:
- `import.py` ran without errors
- The `--neo4j` URL matches the running instance
- Port 7687 is not blocked by a firewall (`nc -zv localhost 7687`)

### Style not applied after `:style` command

- Confirm the HTTP server is running on the expected port: `curl http://localhost:8001/rootstock-style.grass | head -5`
- Try pasting the GraSS content directly: Neo4j Browser → gear icon (⚙) → "Edit stylesheet" → paste file content
- Neo4j Browser may cache styles — try reloading the page

### Guide not loading (`:play` returns an error)

- Confirm HTTP server is running: `curl http://localhost:8001/rootstock-guide.html | head -5`
- Check CORS: Neo4j Browser may block local HTTP servers on some versions.
  Try serving on `0.0.0.0`: `python3 -m http.server 8001 --bind 0.0.0.0`
- **Alternative:** Copy the guide HTML content into `$NEO4J_HOME/import/rootstock-guide.html`
  and reference it via `:play file:///var/lib/neo4j/import/rootstock-guide.html`

### Docker: cannot connect to Neo4j

```bash
docker compose ps        # Verify container is running
docker compose logs neo4j | tail -20   # Check for errors
```

Common causes:
- Container still starting — wait 30 seconds and retry
- Port conflict — another service on 7474 or 7687: `lsof -i :7474`
- Wrong password — check `NEO4J_AUTH` in `docker-compose.yml`

### Inference edges not visible (no attack paths)

Confirm `infer.py` ran successfully:

```cypher
MATCH ()-[r:CAN_INJECT_INTO]->() RETURN count(r) AS injection_edges
```

If `0`, the attacker payload node may be missing:

```cypher
MATCH (a:Application {bundle_id: 'attacker.payload'}) RETURN a
```

If no results, re-run `python3 graph/infer.py --neo4j bolt://localhost:7687`.

---

## Docker Volume Mounts

The `docker-compose.yml` mounts the browser directory into the container:

```yaml
volumes:
  - ./browser:/import/rootstock:ro
```

This means the guide and style sheet are accessible inside the container at
`/import/rootstock/`. To serve them from within the container:

```bash
docker exec -it rootstock-neo4j \
  python3 -m http.server 8001 --directory /import/rootstock
```

Then use `http://localhost:8001/` as the base URL in Neo4j Browser.
