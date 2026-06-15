## Summary
Brief description of the change.

## Type of Change
- [ ] Bug fix
- [ ] New feature / data source
- [ ] New query
- [ ] Documentation
- [ ] Refactoring
- [ ] CI/CD

## Testing
- [ ] `swift build` passes with zero warnings
- [ ] `swift test` passes
- [ ] `ruff check graph/ scripts/ examples/ docs/` passes, if Python/docs changed
- [ ] `(cd graph && pytest tests)` passes, if graph code changed
- [ ] Neo4j lane run for graph import/inference/query/report/API changes
- [ ] cve-scan lint/tests pass, if `modules/cve-scan/` changed
- [ ] New tests added for new functionality
- [ ] JSON Schema updated (if output format changed)
- [ ] Tested on macOS (version: ___)

## Checklist
- [ ] Code follows project conventions (see CONTRIBUTING.md)
- [ ] No secrets, credentials, or real scan data included
- [ ] No real graph exports, generated viewers, reports, screenshots, package inventories, or CVE scan outputs included
- [ ] No internal, superseded, deprecated, archive, generated, plan, ledger, or status artifacts included
- [ ] Analysis and remediation scope excludes `deprecated/`, `docs/archive/`, and `docs/deprecated/`
- [ ] Documentation index updated if active docs were added, moved, or removed
- [ ] Documentation updated if needed
