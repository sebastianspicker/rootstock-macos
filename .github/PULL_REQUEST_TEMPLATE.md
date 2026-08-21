## Summary

Briefly describe what changed and why.

## Component Scope

- [ ] Rootstock Core collector or graph
- [ ] cve-scan bridge
- [ ] Rootstock Red
- [ ] Rootstock Blue
- [ ] RootstockMacFacts shared package
- [ ] Documentation or repository automation

## Type of Change

- [ ] Bug fix
- [ ] New feature / data source
- [ ] New query
- [ ] Documentation
- [ ] Refactoring
- [ ] CI/CD

## Testing

- [ ] Strict Swift build/tests pass, if collector code changed
- [ ] `uv run --project graph --locked ruff check ...` passes, if Python/docs changed
- [ ] Graph pytest passes; the required Neo4j lane ran for graph runtime behavior
- [ ] cve-scan locked lint/tests pass, if `modules/cve-scan/` changed
- [ ] TypeScript type-check, bundle, and viewer contracts pass
- [ ] Focused regression tests cover the changed behavior and failure boundary
- [ ] Synthetic fixture and JSON Schema stay aligned, if an output contract changed
- [ ] Tested on macOS (version and architecture: ___)

## Checklist

- [ ] Code follows project conventions in `CONTRIBUTING.md`
- [ ] No secrets, credentials, or real scan data included
- [ ] No real graph exports, viewers, reports, screenshots, package inventories, or CVE scan outputs included
- [ ] Any public screenshot uses the synthetic release fixture and has been privacy-reviewed
- [ ] Every included file is intentional source, configuration, test data, or maintained documentation
- [ ] Documentation index updated if active docs were added, moved, or removed
- [ ] Documentation and changelog updated when public behavior or release notes changed
- [ ] Skipped checks and residual uncertainty are stated in the PR description
- [ ] No license scope was inferred or assigned for `packages/RootstockMacFacts/`
