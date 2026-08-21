# Changelog

Public changes to Rootstock are recorded here. The public history begins with
the first alpha. Earlier repository snapshots were not published releases.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Unreleased

### Changed

- Added four Playwright captures of the maintained viewer.
- Aligned public documentation with the separate Core, Red, Blue, and shared
  package build and artifact boundaries.
- Expanded the release structure and CI checks to cover the family Swift
  packages and require public candidate files to be Git-tracked.
- Aligned Rootstock Blue bundle metadata with its `0.4.0-dfir` runtime label.
- Kept synthetic signing fixtures free of private-key-shaped content.
- Added a collector-specific package README and exact package file-set check.
- Documented implemented graph prerequisites and modeled-result boundaries.

## [0.1.0-alpha.1] - Unreleased

Proposed first public Core alpha. No tag, release, or archive has been published
from this candidate.

### Added

- Swift collector for local macOS security metadata with schema-validated JSON
  output and independent data-source modules.
- Neo4j import, relationship inference, query, diff, report, API, and local
  viewer workflows.
- cve-scan package for explicitly scoped evidence and an optional Core graph
  bridge.
- Rootstock Red source package for read-only assessment and a separately built,
  authorization-gated lab executable.
- Rootstock Blue source package for offline case handling, artifact parsing,
  detections, and reports.
- Optional Red and Blue family-export import into the Core graph.
- Shared `RootstockMacFacts` Swift package for paths, catalogs, and read-only
  host-posture parsers.
- Locked Python and browser development environments, TypeScript viewer source,
  browser tests, security workflows, and public contribution templates.

### Security

- Restricted the alpha API listen address and Neo4j URI to loopback.
- Required bearer authentication for `/api/*` routes and a token of at least
  32 bytes.
- Kept Core collection local and Red assessment network-disabled by default.
- Kept Red Lab in a separate executable with authorization checks and dry-run
  defaults.
- Added artifact, screenshot, and fixture privacy checks to the release process.
- Masked executable paths in entitlement-extraction debug logs.
- Made Rootstock Blue logical acquisition publish from a sibling staging
  directory, reject existing or overlapping destinations and symlinked source
  entries, and preserve existing case data on failure.
- Disabled Rootstock Blue ZIP import until bounded extraction and rollback can
  be implemented without archive traversal, overwrite, or resource-exhaustion
  risk.

### Alpha limitations

- Schemas, graph vocabulary, query behavior, package layout, and CLI contracts
  may change before a stable release.
- Live Core graph behavior requires Neo4j 5.x and the dedicated integration
  lane.
- The Core API and database connection are loopback-only.
- Collector binaries are not notarized by the current release procedure.
- Rootstock Blue live Endpoint Security operation is not covered by the same
  test matrix as offline analysis.
- Rootstock Blue ZIP import is disabled. Parse an artifact tree extracted by a
  separately controlled process.
- Rootstock Red and Blue are source-only components in the Core alpha release
  procedure and retain independent versions.
- `packages/RootstockMacFacts` is licensed separately under Apache-2.0.

[0.1.0-alpha.1]: https://github.com/sebastianspicker/rootstock
