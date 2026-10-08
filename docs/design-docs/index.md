# Architecture decisions

These decisions explain the repository's language choices, storage, and file
formats. The [architecture guide](../ARCHITECTURE.md) shows how the components
work together today.

## Core decisions

DD-001 through DD-008 are described below. The remaining decisions have
separate pages.

| ID | Title | Status | Summary |
|---|---|---|---|
| DD-001 | Collector Language Choice | Accepted | Swift over Python for native API access and single-binary deployment |
| DD-002 | Graph Database Choice | Accepted | Neo4j for path queries and interactive graph inspection |
| DD-003 | Collector Output Format | Accepted | Single JSON file, one per scan, self-contained |
| DD-004 | No Secret Extraction | Accepted | Metadata only; this is an architectural constraint |
| DD-005 | SQLite Access Strategy | Accepted | Raw C interop via `libsqlite3` (system-provided), no third-party wrapper |
| DD-006 | Entitlement Extraction API | Accepted | Security.framework primary, `codesign` CLI fallback |
| DD-007 | Inferred Relationships | Accepted | Materialize rule-derived relationships after import; traverse them at query time |
| DD-008 | Multi-host Graph Merging | Accepted | Import scans with hostname and scan identifiers through `rootstock-graph-merge-scans` |
| DD-009 | [cve-scan Artifact Bridge](cve-scan-artifact-bridge.md) | Accepted | cve-scan stays separately buildable and Rootstock imports only `rootstock-export.json` |
| DD-010 | [Product Family Architecture](product-family.md) | Accepted | Products build separately and exchange files; shared Swift code contains neutral facts |
| DD-011 | [Family Artifact Bridges](family-artifact-bridges.md) | Accepted | Optional file imports with explicit formats and version checks |
| DD-012 | [Installed Software CVE Matching](installed-software-cve-matching.md) | Accepted | Exact-version NVD `cpeName` lookups, client-side range re-checks, and an offline cache beside the curated registry |
| DD-013 | [Graph Node Identity](graph-node-identity.md) | Accepted | Launch items keyed by `item_key` and XPC services by plist path instead of label |

| DD-014 | [Offline Investigation](offline-investigation.md) | Implemented; review pending | Evidence-backed offline reports, baseline changes, explicit CVE uncertainty and coverage |

### DD-001: Collector Language Choice

Swift provides direct access to Security.framework, Foundation, and macOS C
APIs. SwiftPM builds the collector executable. Users can run it without
installing Python.

### DD-002: Graph Database Choice

Neo4j provides Cypher queries for traversing relationships and finding paths.
Its Browser also lets users inspect the imported graph directly.

### DD-003: Collector Output Format

Each scan is one self-contained JSON file with metadata. This separates local
collection from graph analysis and gives Swift and Python a simple interchange
format.

### DD-004: No Secret Extraction

Rootstock reads security metadata such as ACLs, permissions, entitlements, and
signatures. Product collectors do not export passwords, private keys, or token
values. This constraint applies in code and artifact contracts.

### DD-005: SQLite Access Strategy

macOS includes `libsqlite3`, which Swift imports through the `SQLite3`
system module. This provides the required read access to TCC databases without
adding a wrapper dependency.

### DD-006: Entitlement Extraction API

Two approaches are available for extracting entitlements from app bundles:

- Security.framework (`SecStaticCodeCreateWithPath` → `SecCodeCopySigningInformation`):
  calls the native signing API without launching a process for each app.
- CLI fallback (`codesign -d --entitlements :- <path>`):
  requires launching a process and parsing its output.

Security.framework is the primary extractor. The collector falls back to
`codesign` when the framework call fails. The implementation is in
`collector/Sources/Entitlements/EntitlementExtractor.swift`.

### DD-007: Inferred Relationships

Import collected facts first, then run the modules orchestrated by
`rootstock_graph.inference.infer` to materialize rule-derived relationships.
Queries traverse those stored relationships and may select paths at query
time. An inferred relationship records a rule match, not verified exploitation.

### DD-008: Multi-host Graph Merging

`rootstock-graph-merge-scans` imports multiple scans with per-scan
and per-host identifiers and rejects duplicate hostnames in one command.
Cross-host results remain subject to the completeness and age of each scan.
