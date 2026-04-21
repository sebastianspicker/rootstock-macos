# Contributing to Rootstock

Thank you for your interest in contributing to Rootstock!

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
docker compose up -d                    # Start Neo4j
pip3 install -r requirements.txt        # Install Python deps
python3 setup.py                        # Initialize schema
python3 import.py --input scan.json     # Import collector output
python3 infer.py                        # Compute inferred relationships
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
2. Write tests for new functionality (target: 80%+ coverage)
3. Ensure `swift build` and `swift test` pass with zero warnings
4. Update documentation if you're adding a new data source or query
5. Submit a PR with a clear description of what and why

## Adding a New Data Source

See `.github/ISSUE_TEMPLATE/new_data_source.md` for the template. The key steps:

1. Create a new module in `collector/Sources/<ModuleName>/`
2. Define a Codable model in `collector/Sources/Models/`
3. Implement `DataSource` protocol conformance
4. Add to `ScanOrchestrator` and `ScanResult`
5. Update the JSON Schema
6. Add tests
7. Update graph import if the data source produces new node types

## Reporting Security Issues

If you discover a security vulnerability in Rootstock itself (not in the macOS
systems it analyzes), please report it privately via GitHub Security Advisories
rather than opening a public issue.
