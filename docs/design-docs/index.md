# Design Documents — Index

> Architectural decisions and their rationale.
> Each design doc captures a decision that shapes the project.

## Core Decisions

> Decisions marked *(inline)* are documented here. Those with links have dedicated DD files.

| ID | Title | Status | Summary |
|---|---|---|---|
| DD-001 | Collector Language Choice | Accepted | Swift over Python for native API access and single-binary deployment |
| DD-002 | Graph Database Choice | Accepted | Neo4j for BloodHound ecosystem familiarity and Cypher expressiveness |
| DD-003 | Collector Output Format | Accepted | Single JSON file, one per scan, self-contained |
| DD-004 | No Secret Extraction | Accepted | Metadata only — architectural constraint, not just policy |
| DD-005 | SQLite Access Strategy | Accepted | Raw C interop via `libsqlite3` (system-provided), no third-party wrapper |
| DD-006 | Entitlement Extraction API | Proposed | Security.framework primary, `codesign` CLI fallback. See open questions below |
| DD-007 | Inferred Relationships | Proposed | Which relationships to compute at import time vs. query time |
| DD-008 | Multi-host Graph Merging | Future | How to combine scans from multiple endpoints |

### DD-001: Collector Language Choice
**Status:** Accepted
**Rationale:** Swift gives direct access to Security.framework, Foundation, and macOS C APIs
without FFI overhead. SPM produces a single static binary with no runtime dependencies.
Python was considered but rejected due to poor access to native macOS security APIs and
the need for a runtime.

### DD-002: Graph Database Choice
**Status:** Accepted
**Rationale:** Neo4j was chosen for BloodHound ecosystem familiarity (security practitioners
already know Cypher and the Neo4j Browser) and the expressiveness of Cypher for path queries.
Alternatives considered: ArangoDB (less ecosystem), TigerGraph (commercial), plain SQLite
(insufficient for path traversal).

### DD-003: Collector Output Format
**Status:** Accepted
**Rationale:** Single JSON file per scan, self-contained with metadata. This decouples the
collector (runs on endpoint) from the graph importer (runs on analysis workstation). JSON
is portable, human-readable, and trivially parseable in both Swift and Python.

### DD-004: No Secret Extraction
**Status:** Accepted
**Rationale:** This is an architectural invariant, not a policy. Rootstock reads metadata
(ACLs, permissions, entitlements, signatures) — never passwords, keys, or token values.
This simplifies data handling, avoids liability concerns, and keeps the tool safe to run
on production systems.

### DD-005: SQLite Access Strategy
**Status:** Accepted
**Rationale:** macOS ships `libsqlite3` as a system library. Swift can import it directly
via a system module (`import SQLite3` on Darwin). This avoids third-party dependencies
while providing full SQLite functionality for reading TCC databases. The `sqlite3` C API
is stable and well-documented.

### DD-006: Entitlement Extraction API
**Status:** Proposed — decide after Phase 1 Step 2 (M1)
**Context:** Two approaches exist for extracting entitlements from app bundles:
- **Security.framework** (`SecStaticCodeCreateWithPath` → `SecCodeCopySigningInformation`):
  Faster for bulk scanning, native Swift, but less documented and may fail on SSV-protected
  system apps.
- **CLI fallback** (`codesign -d --entitlements :- <path>`): Well-understood output format,
  works broadly, but slower (process spawn per app) and requires output parsing.
**Current approach:** Implement Security.framework as primary, `codesign` CLI as fallback
for apps where the framework call fails. Revisit after M1 based on real-world reliability.

## Design Doc Template

```markdown
# DD-NNN: [Title]

**Status:** Proposed | Accepted | Superseded
**Date:** YYYY-MM-DD
**Author:** [name]

## Context
What problem or decision prompted this?

## Decision
What did we decide?

## Rationale
Why this option over alternatives?

## Alternatives Considered
What else was evaluated?

## Consequences
What follows from this decision — both positive and negative?
```
