# QUALITY.md — Quality Standards

## Code Quality

### Swift (Collector)
- No force-unwraps (`!`) except in tests with known fixtures
- All public APIs have doc comments
- Error handling via `Result` or `throws` — no silent failures
- Each data source module has at least one unit test with fixture data
- `swift build` completes with zero warnings

### Python (Graph)
- Type hints on all function signatures
- Pydantic models for JSON validation
- Docstrings on all public functions
- `ruff check` passes with zero violations

### Python (cve-scan Module)
- Runtime dependency list stays intentionally small
- `rootstock-export.json` schema changes keep `modules/cve-scan/src/cve_scan/rootstock.py`, `graph/import_cve_scan.py`, and importer tests in sync
- Real scan outputs and caches remain ignored; only synthetic fixtures are committed
- `ruff check .`, `pytest`, and `shellcheck scripts/perf-smoke.sh` pass from `modules/cve-scan/`

### Cypher (Queries)
- Each `.cypher` file starts with a comment block:
  ```cypher
  // Name: [human readable name]
  // Purpose: [what attack path this discovers]
  // Prerequisites: [what data must be in the graph]
  ```
- Queries must return meaningful column aliases, not raw node objects
- Queries should be parameterized where applicable (`$param` syntax)

## Documentation Quality

- Every design decision has a rationale ("why", not just "what")
- Research docs cite sources with links and specify macOS version tested
- README stays in sync with actual project state
- Public docs describe only the active project surface.
- One-off plans, ledgers, status files, audits, paper drafts, announcements,
  investigation notes, deprecated notes, generated reports, remediation packets,
  and retired roadmaps stay out of the committed documentation set.
- Current-status claims must distinguish fast non-Neo4j checks from the live
  Neo4j lane required for graph import, inference, query, report, and API
  semantics.

## Security Quality

- [ ] No secrets in code, config, or test fixtures
- [ ] Collector JSON output contains no passwords, keys, or tokens
- [ ] Test fixtures use synthetic/anonymized data
- [ ] All dependencies reviewed for security implications
- [ ] Collector makes zero network connections (verified via test)

## Academic Quality

- [ ] All code is original or properly attributed
- [ ] Referenced research includes proper citations
- [ ] Results are reproducible from the repository alone
- [ ] Methodology is documented well enough for peer review
