# Contributing Rootstock

Thank you for your interest in contributing to Rootstock.

Rootstock is a passive macOS attack-path discovery tool. Keep collector changes
local-only and read-only. Do not include real scan output, graph exports,
reports, screenshots, package inventories, tokens, hostnames, usernames, or
infrastructure details in issues or pull requests.

Benchmark results default to ignored `docs/private/` storage, and release
binaries default to the ignored root `release/` directory. Do not move either
into the public documentation tree.

## Development Setup

### Prerequisites

- macOS 14 Sonoma or later
- Xcode 15+ / Swift 5.9+ toolchain
- Python 3.10+
- Docker, for Neo4j-backed graph checks

### Building the Collector

```bash
cd collector
swift build
swift build -c release
swift test
```

### Setting Up the Graph Pipeline

```bash
cd graph
NEO4J_AUTH=neo4j/CHANGE_ME docker compose up -d
pip3 install -r requirements.txt
cd ..
NEO4J_PASSWORD=CHANGE_ME bash graph/pipeline.sh examples/demo-scan.json
```

If graph changes affect import, inference, queries, reports, or the API, run the
Neo4j lane instead of relying only on fast unit tests:

```bash
(cd graph && ROOTSTOCK_REQUIRE_NEO4J=1 NEO4J_PASSWORD=CHANGE_ME pytest tests -v --tb=short)
NEO4J_PASSWORD=CHANGE_ME bash tests/integration/test_full_pipeline.sh
```

## Coding Style

### Swift Collector

- Use `UpperCamelCase` for types and `lowerCamelCase` for functions and variables.
- Keep scan models `Codable` with explicit `snake_case` JSON keys.
- Prefer immutable values.
- Make each data source conform to the existing `DataSource` pattern.
- Report recoverable module errors; do not crash the whole collector.

### Python Graph

- Follow PEP 8 and use `snake_case`.
- Add type hints to function signatures.
- Use Pydantic v2 validation for graph models.

### Cypher Queries

- Keep one query per `.cypher` file in `graph/queries/`.
- Include a short comment header with name, purpose, category, and severity.

## Pull Request Process

1. Fork the repository and create a feature branch.
2. Add tests that prove the intended behavior and relevant failure boundaries.
3. Run the narrowest relevant checks, then broader checks for high-risk changes.
4. Update documentation when adding a data source, query, output contract, or operator workflow.
5. Submit a PR that explains what changed, why it changed, and what was verified.

## Adding a Data Source

Use `.github/ISSUE_TEMPLATE/new_data_source.md` as the checklist:

1. Create a module in `collector/Sources/<ModuleName>/`.
2. Define Codable models in `collector/Sources/Models/`.
3. Implement the `DataSource` protocol.
4. Add the data source to `ScanOrchestrator` and `ScanResult`.
5. Update `collector/schema/scan-result.schema.json`.
6. Add focused tests.
7. Update the graph importer if the data source produces new node or edge types.
8. Validate at least one synthetic fixture with `python3 scripts/validate-scan.py`.

## Reporting Security Issues

If you discover a security vulnerability in Rootstock itself, not in macOS
systems analyzed by Rootstock, report it privately through GitHub Security
Advisories instead of opening a public issue.
