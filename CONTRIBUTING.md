# Contributing to Rootstock

Choose the component you want to change and start with its README. The
[product map](docs/FAMILY.md) explains how the tools fit together. If your
change affects a file passed between tools, also read the
[artifact contracts](contracts/README.md).

Do not commit real scan output, graph exports, reports, cases, findings,
screenshots, package inventories, tokens, hostnames, usernames, or
infrastructure details. Treat all of them as confidential. The benchmark script
defaults to ignored private storage, and release binaries use the ignored
`release/` directory. Put any alternate sensitive output outside the checkout.

## Setup

- macOS 14+ and Swift 6.3 for the collector; Red, Blue, and the shared
  package use Swift 6.2+. Swift tests (`swift test`) use Swift Testing, so Xcode is not
  required (`scripts/swift-test`, used by `sh scripts/verify`, adds the plugin
  path for the Command Line Tools toolchain)
- Python 3.11+, `uv`, and Neo4j 5.x for full graph development
- Node.js from `graph/viewer/.node-version` and npm 11.17.0 for the viewer
  and the repository duplication gate
- Docker only when exercising the Neo4j lane

Install only the environments relevant to your work. For example:

```sh
uv sync --project graph --locked --all-extras
uv sync --project modules/cve-scan --locked --all-extras
npm ci --ignore-scripts --prefix graph/viewer  # viewer, web lane
npm ci --ignore-scripts                        # repository root, jscpd gate
export SWIFTLINT_BIN=$(sh scripts/install-swiftlint.sh)  # quality lane
```

What each lane needs:

| Lane | Local setup |
| --- | --- |
| `release` | Python 3.11+ and Node.js; no installs |
| `quality` | Both `npm ci` commands, both `uv sync` commands, and `SWIFTLINT_BIN` |
| `web` | `npm ci` in `graph/viewer` |
| `graph` | `uv sync --project graph` |
| `cve` | `uv sync --project modules/cve-scan` |
| `swift-core`, `swift-family` | Swift toolchain; `swift-family` also needs `uv sync --project graph` |
| `shell` | ShellCheck |
| `neo4j`, `full` | A Neo4j database and credentials (see `docs/QUALITY.md`) |

## Verification

Private test suites and their fixtures stay local and gitignored. Never stage,
force-add, restore into a commit, or publish them. The verification lanes run them
when installed locally; public checkouts run builds, lint, contracts, and smoke
checks. See [Quality gates](docs/QUALITY.md) for the publication boundary.

Run the verification lane for the component you changed:

```sh
sh scripts/verify graph  # example: graph package changes
```

[Quality gates](docs/QUALITY.md) lists every lane and its requirements. Use
`release` for public docs or release-file changes and `full` for all checks.
The `neo4j` lane requires a running local database and separate writer and
reader credentials. Missing tools or services fail the selected lane. Record
any relevant check you could not run and explain why.

## Contract changes

`contracts/` owns checked-in cross-runtime schemas and fixtures. A contract
change must update the owning producer, all supported consumers, valid and
invalid fixtures, the appropriate checker, and its documented compatibility
rule. Do not replace the legacy collector scan schema with an unversioned
breaking change. Add a versioned contract instead.

The graph package is implemented in `graph/src/rootstock_graph/` and exposed
through `rootstock-graph-*` console commands declared in `graph/pyproject.toml`.
Do not recreate root-level Python command adapters. Keep the graph API
loopback-only, bearer-token protected, and read-only for ad-hoc Cypher. Graph
modules follow the layering checked by the private architecture test suite; see
[Architecture](docs/ARCHITECTURE.md#extension-rules).

## Product-specific rules

- Collector sources are local and read-only. Report protected
  evidence that could not be read so users can see gaps in the scan.
- The graph imports cve-scan's completed export. Keep scanner internals out of
  graph code.
- Red Lab actions remain separate, operator-confirmation gated, and dry-run by
  default. Do not describe self-attestation as external authorization.
- Blue event ingestion is synthetic/offline only. Do not present fixture tests
  as live Endpoint Security, signing, entitlement, or deployment validation.
- Product-owned scripts live in the product (`collector/scripts/`,
  `graph/scripts/`, `rootstock-blue/Tools/scripts/`); the root `scripts/`
  directory holds only the verifier and cross-product checkers.
- `RootstockMacFacts` contains neutral facts and parsers, not product models,
  serializers, graph state, or network clients.

Keep maintained authored source, test, and script files at or below 600
physical lines. Use focused behavior tests, preserve public command and
artifact contracts, and update operator documentation with any real behavior
change. Run the lane that covers the component you changed (`sh scripts/verify
graph`, `cve`, `web`, `swift-core`, or `swift-family`), which also runs its private test
suite when installed locally.

Follow the [Code of Conduct](CODE_OF_CONDUCT.md) in project discussions.

## Pull requests

Keep each pull request focused on one product or contract boundary. Describe
the behavior that changed, the checks you ran, and any relevant check you could
not run. Include synthetic fixtures for new evidence shapes; never attach real
host or case data.

Report vulnerabilities in Rootstock itself through the private process in
[SECURITY.md](SECURITY.md), rather than a public issue.
