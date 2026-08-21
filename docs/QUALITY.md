# Quality gates

This document lists the maintained candidate gates. A subset does not establish
that the complete repository is ready for release.

## Core collector

- Build and test with the Swift toolchain required by `collector/Package.swift`.
- Enable complete strict concurrency and warnings as errors.
- Keep JSON schema, Swift coding keys, and graph models aligned.
- Treat incomplete access, including missing Full Disk Access, as an explicit
  result rather than silent success.

```bash
(cd collector && \
  swift build -Xswiftc -strict-concurrency=complete -Xswiftc -warnings-as-errors && \
  swift test --parallel \
    -Xswiftc -strict-concurrency=complete -Xswiftc -warnings-as-errors)
python3 scripts/check-scan-contract-fields.py
```

## Graph and cve-scan

```bash
uv run --project graph --locked ruff check graph/ scripts/ examples/ docs/ \
  --exclude docs/archive --exclude docs/private
uv run --project graph --locked pytest graph/tests
uv run --project graph --locked \
  python scripts/validate-scan.py examples/demo-scan.json

(cd modules/cve-scan && \
  uv run --locked ruff check . && \
  uv run --locked pytest)
```

## Family packages

```bash
(cd packages/RootstockMacFacts && swift build)
(cd rootstock-red && swift build --product rootstock-red && swift test)
(cd rootstock-blue && \
  swift build --product rootstock-blue && swift test && \
  make content-validate && make check-non-goals)
python3 scripts/check-technique-catalog.py
```

Shared macOS vocabulary belongs in `packages/RootstockMacFacts`. Artifact
serializers remain in the component that owns the artifact.

## Viewer

```bash
npm run typecheck
npm run bundle
```

The bundle must be a deterministic product of `graph/viewer-src/`.

## Public repository checks

- Public commands must match implemented entry points.
- The release check verifies index-level Markdown image targets. Check ordinary
  relative documentation links separately before publication.
- Real scans, findings, cases, reports, tokens, local database state, and
  machine-specific benchmark results must remain untracked.
- Public fixtures and images must contain only synthetic identifiers.
- Only maintained documentation and intentional synthetic fixtures belong in
  the public repository.
- License ownership must be explicit for every distributed source scope.

```bash
python3 scripts/check-release.py
git diff --check
```

Immediately before an approved tag, `python3 scripts/check-release.py
--require-clean` must also pass. No release artifact, checksum, tag, or GitHub
release may be claimed before it exists and has been verified.
