# Rootstock

[![Build](https://github.com/sebastianspicker/rootstock/actions/workflows/test.yml/badge.svg)](https://github.com/sebastianspicker/rootstock/actions)
[![Codacy](https://app.codacy.com/project/badge/Grade/8b8c55c173964e039f5b1e7629cca6b2)](https://app.codacy.com/gh/sebastianspicker/rootstock/dashboard)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13235/badge)](https://www.bestpractices.dev/projects/13235)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/sebastianspicker/rootstock/badge)](https://scorecard.dev/viewer/?uri=github.com/sebastianspicker/rootstock)

Rootstock is a repository of macOS security analysis tools. Its core workflow
collects local security metadata into a JSON artifact, imports that artifact
into Neo4j, derives security relationships, and exposes queries, reports, and a
local graph viewer.

The repository also contains independently built Red and Blue packages. They
share macOS security vocabulary with the core but use separate artifacts and
do not feed the core graph unless an operator runs an explicit bridge command.

> Alpha status: the repository version is `0.1.0-alpha.1`. Schemas,
> graph vocabulary, queries, package layout, and command behavior may change.
> No stable compatibility guarantee or production-suitability claim is made.

## Current capabilities

| Component | Implemented role | Primary artifact |
|---|---|---|
| Core collector | Reads local TCC, entitlement, code-signing, persistence, Keychain metadata, XPC, MDM, identity, and related host evidence | `scan.json` |
| Core graph | Validates and imports scans, derives relationships, runs Cypher queries, writes reports, and serves a loopback-only authenticated viewer API | Neo4j data, reports, or viewer HTML |
| cve-scan | Collects explicitly scoped package, service, web, TLS, and IaC evidence and can write a graph bridge artifact | `rootstock-export.json` |
| Rootstock Red | Performs read-only host assessment and writes structured findings; its separate lab executable contains authorization-gated, dry-run-default validation actions | JSON, JSONL, SARIF, or Markdown findings |
| Rootstock Blue | Parses offline macOS artifacts into an incident-response case, timeline, detections, and reports; optional live Endpoint Security surfaces have additional platform requirements | `.rsbcase` case package |

See [Product family](docs/FAMILY.md) for artifact boundaries and optional
interop commands.

## Known limitations

- Core collection is macOS-only and represents a point-in-time host snapshot.
- The collector can return incomplete TCC data without Full Disk Access.
- Graph import, inference, query, report, and API behavior require Neo4j 5.x.
- The core API and its Neo4j connection are intentionally loopback-only in this
  alpha.
- Inferred attack paths describe modeled preconditions. They do not prove that
  exploitation will succeed.
- Red Lab can modify system state only through its separate executable and
  explicit authorization controls. It is not part of the default assessment
  binary.
- Blue live Endpoint Security operation requires signing, entitlements, and
  system approval. Offline fixture-backed behavior has broader test coverage
  than the live extension path.
- Red and Blue retain independent version labels and are source-only components
  in the `0.1.0-alpha.1` core release procedure.

## Requirements

| Surface | Requirement |
|---|---|
| Core collector | macOS 14 or later; Swift 6.3 from Xcode 26.6 |
| Rootstock Red | macOS 13 or later; Swift 6.2 or later |
| Rootstock Blue | macOS 14 or later; Swift 6.2 or later |
| RootstockMacFacts | macOS 13 or later; Swift tools 6.0-compatible toolchain |
| Core graph | Python 3.10 or later; `uv`; Neo4j 5.x |
| cve-scan | Python 3.11 or later; `uv` for locked development environments |
| Viewer development | Node.js from `.node-version`; npm 11.17.0 |
| Neo4j integration tests | Docker or another reachable Neo4j 5.26 Community instance |

The collector manifest requires Swift tools 6.3. A Swift 6.2 toolchain cannot
build it.

## Install and build

### Core collector

```bash
cd collector
swift build -c release
cd ..
```

The release executable is
`collector/.build/release/RootstockCLI`.

### Core graph environment

```bash
uv sync --project graph --locked --all-extras
```

### cve-scan environment

```bash
uv sync --project modules/cve-scan --locked --all-extras
```

### Viewer development environment

```bash
npm ci --no-audit --no-fund --ignore-scripts
npx --no-install playwright install chromium
```

## Configuration

The core graph uses these environment variables:

- `NEO4J_URI`, defaulting to the local Bolt endpoint
- `NEO4J_USER`
- `NEO4J_PASSWORD`
- `ROOTSTOCK_API_TOKEN`, required for `/api/*` routes and at least 32 bytes

Generate a temporary viewer API token with:

```bash
export ROOTSTOCK_API_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
```

The checked-in `.env.example` is a public example only. Do not commit populated
environment files. CVE refresh and scoped network evidence are opt-in; the core
collector itself has no network collection path.

## Core usage

Run a scan:

```bash
collector/.build/release/RootstockCLI --output scan.json
```

Select modules when a narrower scan is sufficient:

```bash
collector/.build/release/RootstockCLI --output scan.json --modules tcc
collector/.build/release/RootstockCLI \
  --output scan.json --modules entitlements,codesigning
```

Validate the artifact:

```bash
uv run --project graph --locked \
  python scripts/validate-scan.py scan.json
```

Start Neo4j and run the graph pipeline:

```bash
(cd graph && NEO4J_AUTH=neo4j/CHANGE_ME docker compose up -d)
NEO4J_PASSWORD=CHANGE_ME uv run --project graph --locked \
  bash graph/pipeline.sh scan.json
```

Start the authenticated local viewer API:

```bash
NEO4J_PASSWORD=CHANGE_ME uv run --project graph --locked \
  bash graph/pipeline.sh scan.json --serve 8000
```

Stop the Compose service without deleting graph data:

```bash
(cd graph && NEO4J_AUTH=neo4j/CHANGE_ME docker compose down)
```

Neo4j stores database and log data in the named volumes declared by
`graph/docker-compose.yml`. `docker compose down` preserves those volumes.
To delete the local database and logs, use the following destructive command
only after confirming that the Compose project contains no data you need:

```bash
(cd graph && NEO4J_AUTH=neo4j/CHANGE_ME docker compose down --volumes)
```

Import an existing cve-scan bridge in the same pipeline run:

```bash
NEO4J_PASSWORD=CHANGE_ME uv run --project graph --locked \
  bash graph/pipeline.sh scan.json \
  --cve-scan-export modules/cve-scan/runs/local/rootstock-export.json
```

The [synthetic examples](examples/README.md) can be used without collecting a
real host. Reports and viewer files belong under ignored output directories.

## Interface screenshots

These images are Playwright captures of the maintained Graphite Laboratory
viewer using the public seven-node synthetic fixture. They exercise the
production template, stylesheet, bundle, evidence dossier, path builder, and
graph filters without reading a real scan. They do not prove live Neo4j or API
behavior.

Select a screenshot to open the full-size capture.

| Overview | Evidence dossier |
|---|---|
| [![Synthetic Paths workspace overview](docs/screenshots/viewer-overview.png)](docs/screenshots/viewer-overview.png) | [![Synthetic Full Disk Access evidence dossier](docs/screenshots/viewer-node-inspector.png)](docs/screenshots/viewer-node-inspector.png) |

| Modeled path | Risk filter |
|---|---|
| [![Synthetic two-hop modeled path](docs/screenshots/viewer-attack-path.png)](docs/screenshots/viewer-attack-path.png) | [![Synthetic attack-path and vulnerability filters](docs/screenshots/viewer-risk-filter.png)](docs/screenshots/viewer-risk-filter.png) |

Capture instructions and privacy rules are in
[docs/screenshots/README.md](docs/screenshots/README.md).

## Development and validation

Run the component checks affected by a change. The complete local candidate
set is:

```bash
# Core collector, requires Swift 6.3
(cd collector && \
  swift build -Xswiftc -strict-concurrency=complete -Xswiftc -warnings-as-errors && \
  swift test --parallel \
    -Xswiftc -strict-concurrency=complete -Xswiftc -warnings-as-errors)

# Shared and family Swift packages
(cd packages/RootstockMacFacts && swift build && swift test)
(cd rootstock-red && swift build --product rootstock-red && swift test)
(cd rootstock-blue && \
  swift build --product rootstock-blue && swift test && \
  make content-validate && make check-non-goals)

# Core graph and contracts
uv run --project graph --locked ruff check graph/ scripts/ examples/ docs/ \
  --exclude docs/archive --exclude docs/private
uv run --project graph --locked pytest graph/tests
python3 scripts/check-scan-contract-fields.py
python3 scripts/check-technique-catalog.py
uv run --project graph --locked \
  python scripts/validate-scan.py examples/demo-scan.json

# cve-scan
(cd modules/cve-scan && uv run --locked ruff check . && uv run --locked pytest)

# Viewer
npm run typecheck
npm run bundle
npm run test:viewer:unit
npm run test:viewer:bundle
npm run test:viewer:performance
npm run test:browser

# Script contracts
bash tests/scripts/test_benchmark.sh

# Release structure
python3 scripts/check-release.py
```

The Neo4j-required lane is separate:

```bash
(cd graph && ROOTSTOCK_REQUIRE_NEO4J=1 NEO4J_PASSWORD=CHANGE_ME \
  uv run --locked pytest tests -v --tb=short)
NEO4J_PASSWORD=CHANGE_ME uv run --project graph --locked \
  bash tests/integration/test_full_pipeline.sh
```

Do not generalize fast tests into live graph verification if this lane did not
run. See [Quality gates](docs/QUALITY.md) and
[Release procedure](docs/RELEASING.md).

## Repository structure

```text
collector/                 Core Swift collector
graph/                     Neo4j import, analysis, reports, API, and viewer
modules/cve-scan/           Optional scoped CVE evidence module
packages/RootstockMacFacts Shared read-only macOS vocabulary
rootstock-red/              Assessment and gated lab Swift packages
rootstock-blue/             DFIR and incident-response Swift packages
examples/                  Synthetic contract fixtures
tests/browser/             Playwright end-to-end tests
tests/integration/         Cross-component integration tests
tests/scripts/             Repository script contract tests
tests/viewer/              Viewer unit, bundle, and performance contracts
tests/fixtures/            Generators for cross-package test fixtures
docs/                      Maintained public documentation
scripts/                   Validation, operational, release, and screenshot tools
```

## Troubleshooting

- `package ... is using Swift tools version 6.3.0`: select a Swift 6.3
  toolchain before building the collector. CI uses Xcode 26.6.
- TCC results are empty on a recent macOS release: grant Full Disk Access to
  the terminal running the collector, then repeat the scan.
- Neo4j connection fails: confirm the container is healthy, the Bolt endpoint
  is loopback, and the configured user and password match. With
  `NEO4J_PASSWORD` set, run
  `uv run --project graph --locked python scripts/check-neo4j-connection.py`.
- The viewer returns `401`: create a new `ROOTSTOCK_API_TOKEN` and enter the
  same value in the viewer session.
- Graph tests are skipped: set `ROOTSTOCK_REQUIRE_NEO4J=1` with a reachable
  Neo4j instance to turn the required integration lane into a hard failure.

More cases are documented in [FAQ](docs/FAQ.md).

## Contributing and security

Read [CONTRIBUTING.md](CONTRIBUTING.md) before changing an artifact contract or
crossing a pillar boundary. Report vulnerabilities through the private channel
in [SECURITY.md](SECURITY.md), not through a public issue.

Real scans, reports, graph exports, case packages, findings, tokens, host data,
and screenshots derived from them are confidential artifacts and must not be
committed.

## License

This repository contains multiple license scopes:

- the core collector, graph, viewer, and root documentation use GPL-3.0 under
  [LICENSE](LICENSE);
- `modules/cve-scan/` uses MIT under its own
  [license](modules/cve-scan/LICENSE);
- `rootstock-red/` and `rootstock-blue/` use Apache-2.0 under their own license
  files.

The shared `packages/RootstockMacFacts/` license scope is not yet explicit.
That ambiguity must be resolved before a public source release containing the
shared package.

Citation metadata for the core candidate is in [CITATION.cff](CITATION.cff).
