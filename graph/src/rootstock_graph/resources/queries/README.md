# Rootstock Cypher queries

The installed graph package includes 120 read-only analysis queries. The CLI
builds its catalog from the name, category, severity, parameter, and purpose
headers in each `.cypher` file. Use that generated catalog for the current list.

## Prepare the graph

From the repository root:

```sh
(cd graph && NEO4J_AUTH=neo4j/CHANGE_ME docker compose up -d)
NEO4J_PASSWORD=CHANGE_ME bash graph/pipeline.sh examples/demo-scan.json \
  --skip-report
```

Use a generated local password instead of `CHANGE_ME`.

## Run packaged queries

```sh
# List every query and its current metadata.
NEO4J_PASSWORD=CHANGE_ME uv run --project graph --locked \
  rootstock-graph-query --list

# Run one query.
NEO4J_PASSWORD=CHANGE_ME uv run --project graph --locked \
  rootstock-graph-query --run 01

# Supply a query parameter.
NEO4J_PASSWORD=CHANGE_ME uv run --project graph --locked \
  rootstock-graph-query --run 17 --param min_permissions=5

# Select a machine-readable format.
NEO4J_PASSWORD=CHANGE_ME uv run --project graph --locked \
  rootstock-graph-query --run 21 --format json
NEO4J_PASSWORD=CHANGE_ME uv run --project graph --locked \
  rootstock-graph-query --run 23 --format csv > /tmp/rootstock-query.csv
```

`--run all` executes every packaged query. Use `--help` for connection and
format options. A query's header describes its Cypher, so update both together
when changing a query.

## Neo4j Browser

For interactive visualization, open `http://localhost:7474` and authenticate
with the password supplied through `NEO4J_AUTH`. The optional
`graph/browser/setup-browser.sh` serves the repository's GraSS stylesheet and
Browser guide on loopback. See the repository
[Neo4j Browser guide](../../../../../docs/guides/neo4j-browser-quickstart.md).

## Interpret results conservatively

A returned row means that the imported evidence matched the query's model. It
does not prove exploitation. Before drawing a conclusion, validate the source
evidence, runtime defenses, application behavior, and operating-system version.

A query that returns no rows does not prove that the host is secure. Check that:

- the latest collector scan imported successfully;
- its `import_status`, collection errors, and skipped TCC evidence are
  understood;
- Full Disk Access was available where the selected query depends on protected
  evidence;
- inference and tier classification completed;
- any required query parameters match the imported graph;
- the query models the behavior being investigated.

Query output can contain confidential host and organization data. Save it in a
private directory and keep it out of source control.

Queries **119** (CVE candidates) and **120** (CVE coverage) distinguish unverified or stale NVD evidence from current version matches. Candidates do not feed CVE risk scoring.
