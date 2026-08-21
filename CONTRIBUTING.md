# Contributing Rootstock

This multi-component alpha repository contains Rootstock Core (`collector/`,
`graph/`, and the optional `modules/cve-scan/` bridge), `rootstock-red/`,
`rootstock-blue/`, and `packages/RootstockMacFacts/`. These components have
separate executables, artifacts, and validation paths. See
[docs/FAMILY.md](docs/FAMILY.md) before cross-component changes.

Core collection is local-only and host-read-only. Do not include real scan
output, graph exports, reports, screenshots, package inventories, tokens,
hostnames, usernames, or infrastructure details in issues or pull requests.
Treat Red findings and Blue case packages as confidential in the same way.

The repository has multiple license scopes. `packages/RootstockMacFacts/` is
Apache-2.0; see the root [README license section](README.md#license) and each
component license file before proposing distribution changes.

Benchmark results default to ignored `docs/private/` storage, and release
binaries default to the ignored root `release/` directory. Do not move either
into the public documentation tree.

## Development Setup

### Prerequisites

- macOS 14 Sonoma or later
- Xcode 26.6 / Swift 6.3 toolchain
- Python 3.11+ for full-repository development; the graph package alone
  supports Python 3.10+
- Node.js 24.18.0 from `.node-version` and npm 11.17.0, for viewer development
  and browser tests; install with `npm ci` after cloning
- uv, for locked Python environments
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
uv sync --project graph --locked --all-extras
NEO4J_AUTH=neo4j/CHANGE_ME docker compose -f graph/docker-compose.yml up -d
NEO4J_PASSWORD=CHANGE_ME uv run --project graph --locked \
  bash graph/pipeline.sh examples/demo-scan.json
```

## Coding Style

Keep tracked, maintained source, test, and script files at or below 600
physical lines. Generated bundles, fixture or data files, vendored and build
content, and archives are excluded. Run the same guard used by CI from the
repository root:

```bash
python3 scripts/check-source-size.py --max-lines 600
```

### Test organization

Keep only direct, behavior-focused unit contracts beside their owning package.
Use inline data or temporary directories rather than fixture trees, and avoid
browser, workflow, and environment-specific automation.

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

### Source Documentation

- Give every authored production module a brief responsibility docstring or
  file-level comment; a documented primary type may serve this role in Swift.
- Document exported or non-trivial functions when ordering, security
  boundaries, resource limits, fallback behavior, or error semantics are not
  obvious from the signature.
- Explain intent and constraints rather than restating syntax. Built
  bundles, lockfiles, fixtures, and trivial accessors do not need commentary.

### Cypher Queries

- Keep one query per `.cypher` file in `graph/queries/`.
- Include a short comment header with name, purpose, category, and severity.

## Pull Request Process

1. Fork the repository and create a feature branch.
2. Add tests that prove the intended behavior and relevant failure boundaries.
3. Run the narrowest relevant checks, then broader checks for high-risk changes.
4. Update documentation when adding a data source, query, output contract, or operator workflow.
5. Submit a PR that identifies the affected component, explains what changed,
   and records what was verified or skipped.

See [docs/RELEASING.md](docs/RELEASING.md) for version alignment, candidate
gates, screenshot handling, and the approval-only publication sequence.

## Adding a Data Source

Use `.github/ISSUE_TEMPLATE/new_data_source.md` as the checklist:

1. Create a module in `collector/Sources/<ModuleName>/`.
2. Define Codable models in `collector/Sources/Models/`.
3. Implement the `DataSource` protocol.
4. Add the data source to `ScanOrchestrator` and `ScanResult`.
5. Update `collector/schema/scan-result.schema.json`.
6. Add focused tests.
7. Update the graph importer if the data source produces new node or edge types.
8. Validate at least one synthetic fixture with
   `uv run --project graph --locked python scripts/validate-scan.py`.

## Reporting Security Issues

If you discover a security vulnerability in Rootstock itself, not in macOS
systems analyzed by Rootstock, report it privately through GitHub Security
Advisories instead of opening a public issue.
