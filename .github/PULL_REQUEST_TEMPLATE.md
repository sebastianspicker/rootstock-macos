## Summary

Briefly describe what changed and why.

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
- [ ] Neo4j lane ran, if graph import/inference/query/report/API behavior changed
- [ ] cve-scan lint/tests pass, if `modules/cve-scan/` changed
- [ ] Tests added for new behavior
- [ ] JSON Schema updated, if output format changed
- [ ] Tested on macOS (version: ___)

## Checklist

- [ ] Code follows project conventions in `CONTRIBUTING.md`
- [ ] No secrets, credentials, or real scan data included
- [ ] No real graph exports, generated viewers, reports, screenshots, package inventories, or CVE scan outputs included
- [ ] No internal, superseded, deprecated, archive, generated, plan, status, or investigation artifacts included
- [ ] Analysis remediation scope excludes private, archive, deprecated, and generated artifact folders
- [ ] Documentation index updated if active docs were added, moved, or removed
- [ ] Documentation updated if needed
