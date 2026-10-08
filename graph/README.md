# rootstock-graph

`rootstock-graph` is Rootstock Core's Python analysis package. It validates and
imports collector, family, and CVE artifacts into Neo4j; derives modeled
relationships; and provides queries, reports, exports, a local API, and offline
or live viewers.

## Offline investigation

`rootstock-graph-investigate scan.json --format html --output reports/investigation.html`
produces a searchable local review queue with linked evidence and coverage.
Add `--baseline earlier-scan.json` for durable changes, or choose `--format json`
for structured output. No database or network connection is made. See
[the investigation guide](../docs/INVESTIGATION.md).

NVD candidates with unresolved conditions or stale, incomplete or legacy caches
are retained separately from scored version evidence. Queries 119 and 120 show
candidates and coverage. Reimport CVEs and rerun scoring after updating caches.

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
`api_support`. The private `tests/test_architecture.py` enforces this, forbids cross-module
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

The pipeline runs inference in two stages around the vulnerability import.
`rootstock-graph-infer --stage edges` creates the inferred relationships that
the vulnerability importer's category heuristics read, then
`rootstock-graph-import-vulnerabilities` links CVEs, and finally
`rootstock-graph-infer --stage score` classifies tiers and computes risk scores
and recommendations from both. Running `rootstock-graph-infer` without
`--stage` does both stages in order; use the staged form, or the pipeline,
when CVE data should influence tiers and scores.

The score stage writes a `risk_score`, `risk_level` and `risk_reasons` on each
application (the plain-language facts behind the number), and
`posture_findings`, `posture_unknown` and a risk level on the Computer node.
Only version-matched CVEs (`AFFECTED_BY`) influence scores and tiers; CVEs
matched by exposure category are `HAS_CVE_CONTEXT` background edges.
Recommendations attach to applications and to the host; query 100 lists them
with the apps or host they apply to, and the report prints that list grouped by
priority.

Individual installed commands are also available:

```sh
NEO4J_PASSWORD=CHANGE_ME uv run --project graph --locked \
  rootstock-graph-import-scan --input examples/demo-scan.json
NEO4J_PASSWORD=CHANGE_ME uv run --project graph --locked \
  rootstock-graph-infer --stage edges
NEO4J_PASSWORD=CHANGE_ME uv run --project graph --locked \
  rootstock-graph-import-vulnerabilities
NEO4J_PASSWORD=CHANGE_ME uv run --project graph --locked \
  rootstock-graph-infer --stage score
NEO4J_PASSWORD=CHANGE_ME uv run --project graph --locked \
  rootstock-graph-report --output /tmp/rootstock-report.md \
  --scan-json examples/demo-scan.json
```

Application, Computer and TCC identity is scan-scoped, so a host that is scanned
again would otherwise appear twice. `rootstock-graph-import-scan`,
`rootstock-graph-merge-scans` and `pipeline.sh` therefore detach-delete every
node carrying the `scan_id` of an earlier scan of the same hostname before
importing (the number of removed nodes is printed). Pass
`--keep-previous-scans` to keep earlier scans side by side; `--replace-host` is
still accepted and is the default behaviour.

Besides applications and privacy grants, the import records host evidence:
`Process` nodes (`INSTANCE_OF` an app, `PARENT_OF` their children, `RUNS_ON` the
host), `NetworkListener` nodes (`LISTENS_ON` from the process and app,
`EXPOSED_ON` the host, flagged `exposed` when not loopback and
`reachable_without_firewall` when the firewall is off), `TrustedCertificate`
nodes from the user and admin trust settings (`TRUSTS_CERTIFICATE`,
`SAME_CERTIFICATE` when an app's signing chain uses it), `BrowserExtension`
nodes (`HAS_EXTENSION` from the browser app) and `InstalledPackage` receipts
(`INSTALLED_BY` from the apps they installed). Their keys start with the
`scan_id`, so replacing a host removes them too. Account, remote-control,
Software Update, DNS, proxy and hosts-file settings are properties of the
Computer node. A `LaunchItem` is keyed by `item_key` (`<type>:<path>:<label>`)
and an `XPC_Service` by its plist `path`, so two plists that share a label stay
two nodes; both keep `label` as an indexed property. Launch items also carry
their arguments, `DYLD_*` environment (as `KEY=value` strings), triggers, load
state, program hash and containing app bundle. Queries 106-118 cover this
evidence.

Use `rootstock-graph-query --list` for the packaged query catalog. The packaged
[query guide](src/rootstock_graph/resources/queries/README.md) explains result
interpretation without duplicating the CLI-generated list.

### CVE matching for installed software

Version-matched CVEs come from two sources. Rootstock's curated registry links a
small set of macOS-relevant CVEs by bundle id and version range
(`AFFECTED_BY {match_tier: 'precise'}`). NVD matching covers the installed
versions of catalogued third-party apps and the macOS release itself
(`AFFECTED_BY {match_tier: 'cpe', match_source: 'nvd', cpe}`); see
[DD-012](../docs/design-docs/installed-software-cve-matching.md).

```sh
# List the scan's CPE targets and the apps the catalogue does not cover (offline)
uv run --project graph --locked rootstock-graph-cve-enrichment \
  --list-cpe-targets --scan-json scan.json
# Query NVD for those targets and cache the results
NVD_API_KEY=OPTIONAL uv run --project graph --locked rootstock-graph-cve-enrichment \
  --fetch --scan-json scan.json
# Link cached matches (no network access)
NEO4J_PASSWORD=CHANGE_ME uv run --project graph --locked \
  rootstock-graph-import-vulnerabilities --scan-json scan.json
```

`graph/pipeline.sh --refresh-cve` runs the fetch step for the pipeline's scan.
Results are cached in `~/.rootstock/cache/nvd-installed.json` for seven days;
without `--fetch`, or when NVD cannot be reached, the cached data is used and
uncached targets are reported. `NVD_API_KEY` is optional and raises the NVD rate
limit; it is sent as a request header and never cached. The bundle id to CPE
mapping lives in `src/rootstock_graph/vulnerability/cpe_catalog.py`; extend it
for apps that `--list-cpe-targets` reports as uncatalogued. Queries 104 and 105
list NVD matches per app and for the macOS release.

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

The API checks at startup whether the read account can write (a rolled-back
`CREATE`). Neo4j Community, which the bundled Docker Compose file and CI use,
has no role-based access control, so the check only warns there and ad-hoc
Cypher relies on the statement validator. On Enterprise, grant the read
account the `reader` role and set `ROOTSTOCK_REQUIRE_READONLY_PRINCIPAL=1` to
refuse startup unless the write is denied.

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

The graph lane runs Ruff, contract and scan-model checks,
synthetic scan validation with `rootstock-graph-validate-scan`, and an isolated
wheel smoke test. The web lane needs `npm ci --ignore-scripts` in
`graph/viewer`; it type-checks and lints the viewer, then compares a temporary build with the
packaged assets in the working tree. Run `npm run bundle` in `graph/viewer` to
refresh those assets. Both lanes also run private test suites when installed
locally; those suites and their fixtures are not published. Test a live Neo4j
connection and API separately:

```sh
NEO4J_PASSWORD=CHANGE_ME_WRITE \
NEO4J_READ_USER=rootstock_graph_read \
NEO4J_READ_PASSWORD=CHANGE_ME_READ \
  sh scripts/verify neo4j
```

Configuration, secrets, trusted inputs, and output handling are documented in
[`docs/CONFIGURATION.md`](../docs/CONFIGURATION.md). Real database contents,
reports, viewers, tokens, and query history are confidential local artifacts.
