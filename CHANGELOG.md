# Changelog

## Repository naming migration

The repository moves from `sebastianspicker/rootstock` to
`sebastianspicker/rootstock-macos`. Product commands, data formats, and runtime
identifiers remain unchanged. The demo moves to
https://sebastianspicker.github.io/rootstock-macos/.

This changelog records user-visible changes to Rootstock. The versioned
entries begin with the first Core alpha.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Unreleased

### Changed

- Redesigned the viewer, the snapshot summary export, the graph and CVE HTML
  reports, and the Pages demo and screenshot tour around one flat,
  sans-serif interface with standard severity colours. Inferred and modeled
  material is now violet, actions are blue, and collection gaps are amber.
  The assessment flow uses plain labels, and "Return to evidence folio" is
  now "Back to assessment".
- Node and relationship kinds keep acronyms whole, for example
  "TCC Permission" instead of "T C C Permission".
- Kept private test suites and their fixtures out of the public repository;
  verification lanes run them only when installed locally.
- Scan validation is the installed `rootstock-graph-validate-scan` command;
  `scripts/validate-scan.py` is removed. Arguments, output, and exit codes are
  unchanged.
- The graph viewer's Node project moved to `graph/viewer/` (run `npm ci`,
  `npm run bundle`, and the demo commands there); the root `package.json` now
  holds only repository quality tooling. The collector release and benchmark
  scripts moved to `collector/scripts/`.
- The Rootstock Blue library product `RootstockBlueExport` is renamed
  `RootstockBlueInterchange`; Blue sources moved to `rootstock-blue/Sources/`.
- Swift tests use Swift Testing, so the CommandLineTools are enough to run them.

- Added an interactive synthetic viewer demo and a four-screen tour for the
  README and GitHub Pages, with a reproducible browser capture command.
- Ignore standard scan and report filenames inside component directories, plus
  common private-key and credential filenames.
- Documented installation, commands, and supported file exchange for Core,
  cve-scan, Red, Blue, and the shared Swift package.
- Added release and CI checks for the shared Swift packages and required
  public release inputs to be tracked in Git.
- Aligned Rootstock Blue bundle metadata with its `0.4.0-dfir` runtime label.
- Added a collector-specific package README and exact package file-set check.
- Documented graph prerequisites and how to interpret modeled results.

### Fixed

- Rootstock Blue no longer rejects valid cases when an event or custody
  timestamp falls in the last millisecond of a second.
- The Rootstock Blue unified-logs sidecar can always be stopped by its
  process-group termination, even when the caller blocks SIGTERM.
- Rootstock Blue exports refuse to write into the input case even when the
  case lives under `/tmp` or `/var`, where macOS path resolution previously
  let a report land inside the case.
- `rootstock-graph-validate-scan` reports a non-object JSON document as an
  invalid scan instead of crashing.

## [0.1.0-alpha.1] (release candidate)

First Core alpha candidate. Commands, schemas, and packaging may change
before a stable release.

### Added

- Swift collector for local macOS security metadata with schema-validated JSON
  output and independent data-source modules.
- Neo4j import, relationship inference, query, diff, report, API, and local
  viewer workflows.
- cve-scan package for explicitly scoped evidence and an optional Core graph
  bridge.
- Rootstock Red source package for read-only assessment and a separately built,
  lab executable with an authorization acknowledgement and dry-run default.
- Rootstock Blue source package for offline case handling, artifact parsing,
  detections, and reports.
- Optional Red and Blue family-export import into the Core graph.
- Shared `RootstockMacFacts` Swift package for paths, catalogs, and read-only
  host-posture parsers.
- Locked Python and Node development environments, TypeScript viewer source,
  security workflows, and public contribution templates.

### Security

- Restricted the alpha API listen address and Neo4j URI to loopback.
- Required bearer authentication for `/api/*` routes and a token of at least
  32 bytes.
- Kept Core collection local and Red assessment network-disabled by default.
- Kept Red Lab in a separate executable with operator self-attestation and
  dry-run defaults.
- Added artifact and synthetic-demo privacy checks to the release process.
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
- Rootstock Blue event ingestion is synthetic/offline only; no live Endpoint
  Security client or deployment surface ships in this release.
- Rootstock Blue ZIP import is disabled. Parse an artifact tree extracted by a
  separately controlled process.
- Rootstock Red and Blue are source-only components in the Core alpha release
  procedure and retain independent versions.
- `packages/RootstockMacFacts` is licensed separately under Apache-2.0.

[0.1.0-alpha.1]: https://github.com/sebastianspicker/rootstock-macos
