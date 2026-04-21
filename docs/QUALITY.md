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
- Exec-plans have concrete acceptance criteria with checkboxes
- README stays in sync with actual project state

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
