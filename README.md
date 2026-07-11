# rootstock

[![Build](https://github.com/sebastianspicker/rootstock/actions/workflows/test.yml/badge.svg)](https://github.com/sebastianspicker/rootstock/actions)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/8b8c55c173964e039f5b1e7629cca6b2)](https://app.codacy.com/gh/sebastianspicker/rootstock/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13235/badge)](https://www.bestpractices.dev/projects/13235)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/sebastianspicker/rootstock/badge)](https://scorecard.dev/viewer/?uri=github.com/sebastianspicker/rootstock)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

Rootstock is a passive macOS attack-path discovery tool. It maps local security
boundaries such as TCC grants, entitlements, code signing, Keychain ACLs, XPC
trust, persistence, and enterprise identity artifacts into an analyzable graph.

Think BloodHound-style graph analysis for macOS-native trust relationships, with
a collector that stays local and read-only.

## What It Maps

- **TCC grants** - camera, microphone, Full Disk Access, Apple Events, and other privacy permissions
- **Entitlements** - code-signing privileges that weaken or bypass macOS security boundaries
- **Code signing** - hardened runtime, library validation, team identifiers, and certificate metadata
- **Injection paths** - per-app assessment of DYLD, Electron, and related injection viability
- **Persistence** - LaunchAgents, LaunchDaemons, login items, shell hooks, and related startup paths
- **Keychain and XPC trust** - ACL metadata, service relationships, and trust edges
- **Enterprise context** - Active Directory binding, Kerberos artifacts, MDM profiles, and BloodHound interop
- **Vulnerability context** - CVE/EPSS/KEV enrichment and ATT&CK technique mapping

## Current Public Surface

The maintained public surface is the Swift collector, Python/Neo4j graph
pipeline, `modules/cve-scan/`, synthetic examples, this README, and the
[documentation index](docs/README.md).

Completed audit packets, one-off plans, status files, investigation notes,
deprecated drafts, generated reports, generated viewers, real scan outputs,
and historical roadmaps are not part of public documentation set. Keep local
copies in ignored private or archive paths.

The repository intentionally tracks synthetic fixtures, synthetic screenshots,
the public `.env.example`, and analyzer scope in `.codacy.yaml`. Local analyzer
state, benchmark results, release binaries, databases, real host inventories,
and security reports are ignored.

## Architecture

Rootstock has three active components:

1. `collector/` - a SwiftPM package that runs on the Mac being assessed and
   emits one portable scan JSON file.
2. `graph/` - a Python Neo4j pipeline that imports scan JSON, creates graph
   relationships, classifies risk, runs queries, writes reports, and can serve
   an authenticated viewer API.
3. `modules/cve-scan/` - a scoped Python evidence module that writes local CVE
   artifacts and a `rootstock-export.json` bridge for graph import.

`examples/demo-scan.json` is the synthetic demo fixture source of truth.
Generated demo reports and viewers are local artifacts.

The scan JSON is the main contract. When collector output changes, keep
`collector/schema/scan-result.schema.json`, `graph/models.py`, importer code,
and at least one synthetic fixture in sync:

```bash
python3 scripts/validate-scan.py examples/demo-scan.json
```

## Quick Start

### Requirements

Collector:

- macOS 14 Sonoma or later
- Swift 5.9+ / Xcode 15+

Graph pipeline:

- Python 3.10+
- Neo4j 5.x, Docker recommended

### Build the Collector

```bash
cd collector
swift build -c release
```

### Run a Scan

```bash
collector/.build/release/RootstockCLI --output scan.json
```

Useful variants:

```bash
collector/.build/release/RootstockCLI --output scan.json --verbose
collector/.build/release/RootstockCLI --output scan.json --modules tcc
collector/.build/release/RootstockCLI --output scan.json --modules entitlements,codesigning
sudo collector/.build/release/RootstockCLI --output scan.json
```

macOS 15+ can require Full Disk Access for TCC database reads. Grant FDA to the
terminal or run the collector with the required privileges when you need TCC
grants.

### Validate Output

```bash
python3 scripts/validate-scan.py scan.json
```

### Run the Graph Pipeline

```bash
python3 -m pip install -r graph/requirements.txt
(cd graph && NEO4J_AUTH=neo4j/CHANGE_ME docker compose up -d)
NEO4J_PASSWORD=CHANGE_ME bash graph/pipeline.sh scan.json
```

Import a prebuilt cve-scan artifact in the same run:

```bash
NEO4J_PASSWORD=CHANGE_ME bash graph/pipeline.sh scan.json \
  --cve-scan-export modules/cve-scan/runs/local/rootstock-export.json
```

Start the authenticated API/viewer:

```bash
ROOTSTOCK_API_TOKEN=CHANGE_ME_API_TOKEN NEO4J_PASSWORD=CHANGE_ME \
  bash graph/pipeline.sh scan.json --serve 8000
```

Environment variables:

- `NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASSWORD` - Neo4j connection
- `ROOTSTOCK_API_TOKEN` - required for `/api/*` routes

CVE network refresh is opt-in with `--refresh-cve`; the default pipeline uses
cached/static enrichment.

## Demo Outputs

| Output | Description |
|--------|-------------|
| [`examples/demo-scan.json`](examples/demo-scan.json) | Synthetic collector scan fixture |
| [`examples/cve-scan-export.json`](examples/cve-scan-export.json) | Synthetic cve-scan graph fixture |
| [`modules/cve-scan/docs/example-outcome.md`](modules/cve-scan/docs/example-outcome.md) | Example cve-scan artifact shape |

Generate local demo report/viewer artifacts with:

```bash
bash examples/regenerate.sh
```

The generated files are written under `examples/generated/` and ignored by git.

## Screenshots

Screenshots use synthetic demo data from `examples/demo-scan.json`.

| | |
|---|---|
| ![Full graph](docs/screenshots/01-full-graph.png) | ![Attack path](docs/screenshots/02-attack-path.png) |
| ![Node inspector](docs/screenshots/03-node-inspector.png) | ![Electron inheritance](docs/screenshots/04-electron-inheritance.png) |
| ![Report summary](docs/screenshots/05-report-summary.png) | ![Attack path diagram](docs/screenshots/06-attack-path-diagram.png) |
| ![CVE table](docs/screenshots/07-cve-table.png) | ![Tier pie chart](docs/screenshots/08-tier-pie.png) |

![Collector CLI output](docs/screenshots/09-cli-output.png)

## Verification

```bash
# Swift collector
(cd collector && swift test --parallel)

# Python graph
ruff check graph/ scripts/ examples/ docs/
(cd graph && pytest tests)

# Contract fixture
python3 scripts/validate-scan.py examples/demo-scan.json

# cve-scan module
(cd modules/cve-scan && ruff check . && pytest)

# Shell entry points
shellcheck examples/regenerate.sh graph/pipeline.sh scripts/*.sh tests/integration/*.sh
shellcheck modules/cve-scan/scripts/perf-smoke.sh
bash tests/integration/test_benchmark_script.sh
```

Graph behavior that depends on import, inference, query, report, or API
semantics needs a reachable Neo4j test database:

```bash
(cd graph && NEO4J_AUTH=neo4j/CHANGE_ME docker compose up -d)
(cd graph && ROOTSTOCK_REQUIRE_NEO4J=1 NEO4J_PASSWORD=CHANGE_ME pytest tests -v --tb=short)
NEO4J_PASSWORD=CHANGE_ME bash tests/integration/test_full_pipeline.sh
```

Do not claim graph runtime behavior verified unless the Neo4j lane ran.

## Documentation

- [Documentation index](docs/README.md)
- [Threat model](docs/THREAT_MODEL.md)
- [FAQ](docs/FAQ.md)
- [Neo4j Browser quickstart](docs/guides/neo4j-browser-quickstart.md)
- [cve-scan module guide](docs/guides/cve-scan-module.md)
- [Quality gates](docs/QUALITY.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)

## macOS Compatibility

| macOS Version | Collector | User TCC.db | System TCC.db | Notes |
|---|---|---|---|---|
| 14 Sonoma | Full | Normal read | Requires FDA | Primary supported baseline |
| 15 Sequoia | Full | Requires FDA | Requires FDA | Kernel-enforced TCC access |
| 26 Tahoe | Full | Requires FDA | Requires FDA | Year-based macOS versioning |
| < 14 | Not supported | Not supported | Not supported | Out of scope |

## Threat Model

Rootstock is passive and local-first. The collector reads macOS metadata and
writes a local scan artifact. It must not upload scans, collect telemetry, or
perform active exploitation. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

Treat real scan JSON, graph exports, generated viewers, reports, Neo4j volumes,
screenshots, package inventories, and cve-scan outputs as confidential local
data.

## License

Rootstock is licensed under GPLv3. See [LICENSE](LICENSE).

## Citing Rootstock

```bibtex
@software{rootstock2026,
  title = {Rootstock: Graph-Based Attack Path Discovery for macOS Security Boundaries},
  author = {Sebastian J. Spicker},
  year = {2026},
  url = {https://github.com/sebastianspicker/rootstock},
  note = {Open-source research tool, Cologne University of Music}
}
```
