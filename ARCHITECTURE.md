# Architecture

Rootstock is organized around explicit artifacts rather than a shared runtime.
The Core collector and graph form the main pipeline. cve-scan can add scoped
evidence to that graph. Rootstock Red and Rootstock Blue have separate command
lines, data models, and version identities.

## System map

```text
macOS endpoint
    |
    | RootstockCLI writes scan.json
    v
artifact validation
    |
    v
Neo4j import -> relationship inference -> queries, reports, API, viewer
    ^
    |
    +-- optional cve-scan rootstock-export.json
    +-- optional Red or Blue family-export.json

Rootstock Red: host assessment -> findings or project bundle
Rootstock Blue: artifact tree -> .rsbcase -> timeline, detections, reports
RootstockMacFacts: shared read-only Swift facts used at build time
```

No Red or Blue artifact enters the Core graph unless an operator invokes the
family importer. cve-scan runs independently and the Core pipeline imports only
its completed bridge artifact.

## Core collector

Entry point:
`collector/Sources/RootstockCLI/RootstockCommand.swift`

The command configures module selection and output. `ScanOrchestrator` runs
independent data sources concurrently, then performs enrichment that depends on
the collected application inventory. Each module returns its own result and
recoverable errors so one inaccessible source does not invalidate all other
evidence.

The collector reads macOS metadata for implemented surfaces including TCC,
entitlements, code signing, XPC, Keychain ACLs, persistence, MDM, users and
groups, remote access, login sessions, authorization, system extensions,
sudoers, processes, file ACLs, shell hooks, physical security posture,
Active Directory, Kerberos artifacts, sandbox profiles, and quarantine.

The public contract is
`collector/schema/scan-result.schema.json`. The same top-level model is
represented by Swift coding keys and `graph/models.py`. The script
`scripts/check-scan-contract-fields.py` checks their alignment.

The collector has no network collection path. It writes the output file chosen
by the operator. Protected sources can require root, Full Disk Access, or both.

## Core validation and graph pipeline

`scripts/validate-scan.py` checks a collector artifact against the JSON Schema
and the Pydantic model before import.

Validate an artifact before import with `scripts/validate-scan.py`.
`graph/pipeline.sh` then coordinates:

1. Neo4j schema setup;
2. optional CVE data refresh;
3. node and relationship import;
4. optional prebuilt cve-scan import;
5. relationship inference and vulnerability import;
6. tier classification;
7. optional report output and local API service.

Graph writes use batched parameterized Cypher. Import operations preserve scan
identity so multiple artifacts can coexist and be compared. Relationship
inference is a model of observed preconditions, not proof of exploitability.

The Python package metadata and lock are in `graph/pyproject.toml` and
`graph/uv.lock`.

## cve-scan boundary

`modules/cve-scan/` is a separate Python package with the console entry point
`cve-scan`. It gathers explicitly scoped package, repository, container,
service, web, TLS, and configuration evidence. Network access and feed refresh
occur only through the selected command and scope.

The Core integration artifact is `rootstock-export.json`, currently schema
version 7. `graph/import_cve_scan.py` validates identifiers, labels,
relationship types, and edge endpoints before writing to Neo4j. The Core does
not import cve-scan Python internals.

## API and viewer

`graph/server.py` exposes the live viewer and JSON API. The alpha server accepts
only loopback listen addresses and loopback Neo4j URIs. All `/api/*` routes
require a bearer token. The HTML page at `/` contains no graph data and obtains
data through authenticated same-origin requests.

Viewer source is split across `graph/viewer_template.html`, `graph/viewer.css`,
and `graph/viewer-src/`. `npm run bundle` generates
`graph/viewer.bundle.js`. Offline viewer files use the same renderer but
embed their supplied graph artifact.

## Rootstock Red

Rootstock Red is a Swift package rooted at `rootstock-red/Package.swift`.
`rootstock-red` runs the read-only assessment graph and writes findings,
reports, or a project bundle. Network egress is disabled unless the operator
selects `--allow-network`.

`rootstock-red-lab` is a separate executable. It requires authorization
metadata, defaults to dry-run, and can create or remove documented lab state
only through explicit non-dry-run commands. The additional transport and
adapter targets are unlinked skeletons and are not part of the supported
assessment runtime.

The public finding contract is documented in
`rootstock-red/docs/FINDING_SCHEMA.md`.

## Rootstock Blue

Rootstock Blue is a Swift package rooted at `rootstock-blue/Package.swift`.
Its CLI creates a `.rsbcase` package, imports or parses artifacts into normalized
events, maintains custody records, runs local detection content, and writes
timeline or report output.

Offline fixture-backed analysis is the primary tested alpha path. The Endpoint
Security surface uses mock injection by default. A live deployment requires
Apple entitlements and system approvals that are outside the source-only test
path.

The case contract is documented in
`rootstock-blue/docs/case-package-v0.md`.

## Shared Swift facts

`packages/RootstockMacFacts` contains shared paths, TCC names, launchd parsing,
and read-only host-posture parsers. It does not own collector scans, Red
findings, Blue events, Neo4j access, case storage, or network clients.

Its license scope is unresolved. This must be decided before public
distribution of the shared package and its consumers.

## Interoperability

The optional family schema is owned by
`docs/design-docs/family-artifact-bridges.md`. Red and Blue exporters write
component provenance and a host-to-finding representation. The Core importer
validates that artifact before Neo4j writes.

The bridge does not replace the native Red findings model, Blue case model, or
Core collector schema. Breaking changes must be versioned at the owning
contract and covered by cross-component fixtures.

## Local and runtime state

The following are runtime or development outputs and are not source:

- Swift `.build/` and `.swiftpm/` directories
- Python virtual environments and caches
- `node_modules/`, Playwright reports, traces, and routine screenshots
- Neo4j data and log directories
- real scans, cve-scan runs, Red projects, and Blue cases
- reports, viewers, benchmark results, release archives, and checksums

The public repository contains only synthetic fixtures and the four reviewed
viewer screenshots described in `docs/screenshots/README.md`.
