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

- macOS 14+ and Xcode 26.6 / Swift 6.3 for the collector
- Python 3.11+, `uv`, and Neo4j 5.x for full graph development
- Node.js from `.node-version` and npm 11.17.0 for the viewer
- Docker only when exercising the Neo4j lane

Install only the environments relevant to your work. For example:

```sh
uv sync --project graph --locked --all-extras
uv sync --project modules/cve-scan --locked --all-extras
npm ci --ignore-scripts
```

## Verification

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
loopback-only, bearer-token protected, and read-only for ad-hoc Cypher.

## Product-specific rules

- Collector sources are local and read-only. Report protected
  evidence that could not be read so users can see gaps in the scan.
- The graph imports cve-scan's completed export. Keep scanner internals out of
  graph code.
- Red Lab actions remain separate, operator-confirmation gated, and dry-run by
  default. Do not describe self-attestation as external authorization.
- Blue event ingestion is synthetic/offline only. Do not present fixture tests
  as live Endpoint Security, signing, entitlement, or deployment validation.
- `RootstockMacFacts` contains neutral facts and parsers, not product models,
  serializers, graph state, or network clients.

Keep maintained authored source, test, and script files at or below 600
physical lines. Use focused behavior tests, preserve public command and
artifact contracts, and update operator documentation with any real behavior
change.

Follow the [Code of Conduct](CODE_OF_CONDUCT.md) in project discussions.

## Pull requests

Keep each pull request focused on one product or contract boundary. Describe
the behavior that changed, the checks you ran, and any relevant check you could
not run. Include synthetic fixtures for new evidence shapes; never attach real
host or case data.

Report vulnerabilities in Rootstock itself through the private process in
[SECURITY.md](SECURITY.md), rather than a public issue.
