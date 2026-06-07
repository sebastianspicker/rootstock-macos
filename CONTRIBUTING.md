# Contributing to Rootstock

Thank you for your interest in contributing to Rootstock.

Rootstock is a passive macOS attack-path discovery tool. Keep collector changes
local-only and read-only, and do not include real scan output, graph exports,
reports, screenshots, package inventories, tokens, hostnames, usernames, or
infrastructure details in issues or pull requests.

## Development Setup

### Prerequisites

- macOS 14 (Sonoma) or later
- Xcode 15+ / Swift 5.9+ toolchain
- Python 3.10+
- Docker (for Neo4j)

### Building the Collector

```bash
cd collector
swift build           # Debug build
swift build -c release # Release build
swift test            # Run all tests
```

### Setting Up the Graph Pipeline

```bash
cd graph
NEO4J_AUTH=neo4j/CHANGE_ME docker compose up -d
pip3 install -r requirements.txt
cd ..
NEO4J_PASSWORD=CHANGE_ME bash graph/pipeline.sh examples/demo-scan.json
```

For graph changes that affect import, inference, queries, reports, or the API,
run the required Neo4j lane instead of relying only on fast unit tests:

```bash
(cd graph && ROOTSTOCK_REQUIRE_NEO4J=1 NEO4J_PASSWORD=CHANGE_ME pytest tests -v --tb=short)
NEO4J_PASSWORD=CHANGE_ME bash tests/integration/test_full_pipeline.sh
```

## Coding Style

### Swift (Collector)
- `UpperCamelCase` for types, `lowerCamelCase` for functions/variables
- All models are `Codable` with `snake_case` JSON keys via `CodingKeys`
- Immutable data: create new objects, never mutate existing ones
- Each data source conforms to the `DataSource` protocol
- Graceful degradation: modules report errors, never crash the collector

### Python (Graph)
- PEP 8, `snake_case` throughout
- Type hints for function signatures
- Pydantic v2 for data validation

### Cypher Queries
- One query per `.cypher` file in `graph/queries/`
- Comment header with: Name, Purpose, Category, Severity

## Pull Request Process

1. Fork the repository and create a feature branch
2. Write tests that prove the intended behavior, including failure and boundary cases when relevant
3. Run the narrowest relevant checks, then broader checks for high-risk changes
4. Update documentation if you're adding a new data source, query, output contract, or operator workflow
5. Submit a PR with a clear description of what changed, why it changed, and what was verified

## Adding a New Data Source

See `.github/ISSUE_TEMPLATE/new_data_source.md` for the template. The key steps:

1. Create a new module in `collector/Sources/<ModuleName>/`
2. Define a Codable model in `collector/Sources/Models/`
3. Implement `DataSource` protocol conformance
4. Add to `ScanOrchestrator` and `ScanResult`
5. Update the JSON Schema
6. Add tests
7. Update graph import if the data source produces new node types
8. Validate at least one synthetic fixture with `python3 scripts/validate-scan.py`

## Reporting Security Issues

If you discover a security vulnerability in Rootstock itself (not in the macOS
systems it analyzes), please report it privately via GitHub Security Advisories
rather than opening a public issue.
