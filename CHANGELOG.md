# Changelog

## Unreleased — investigation workflow

- Offline `rootstock-graph-investigate` command with searchable HTML, JSON/text,
  evidence associations, stable identifiers, source fingerprints, collection
  coverage and same-host baseline changes.
- NVD Boolean configuration handling, CPE part checks, rejected-CVE filtering,
  conditional qualifiers, parser/cache provenance and partial-fetch reporting.
- Separate unverified CVE candidate edges, per-product coverage queries, preserved
  registry/NVD evidence and per-host/per-installation NVD update recommendations.

## Repository naming migration

The repository moves from `sebastianspicker/rootstock` to
`sebastianspicker/rootstock-macos`. Product commands, data formats, and runtime
identifiers remain unchanged. The demo moves to
https://sebastianspicker.github.io/rootstock-macos/.

This changelog records user-visible changes to Rootstock. The versioned
entries begin with the first Core alpha.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Unreleased

### Added

- Collector: Electron apps now record the `RunAsNode` fuse state
  (`electron_run_as_node`). The `electron_env_var` injection vector is reported
  only when the fuse is enabled or unreadable, which removes false findings for
  modern Electron builds that disable `ELECTRON_RUN_AS_NODE`.
- Collector: launch items record the team and signing identifier of their
  program (`program_team_id`, `program_signing_id`), and applications record
  the Gatekeeper assessment source (`gatekeeper_assessment`). The graph links a
  LaunchDaemon or LaunchAgent to the app that installed it by program path, by
  signing team, or by a label namespaced under the app's bundle id
  (`PERSISTS_VIA.match`).
- Collector: the scan ends with a grouped coverage summary that names each
  source with gaps and the action that closes them (grant Full Disk Access to
  the terminal, rerun with `sudo`).
- Graph: every scored application carries `risk_reasons`, the plain-language
  facts behind its score; the Computer node carries `posture_findings`,
  `posture_unknown` and its own risk level. Both appear in the viewer, the
  snapshot export and the report's executive summary.
- Graph: recommendations are written for the person administering the Mac and
  attach to the host as well as to apps (FileVault, firewall, screen lock, Remote
  Login, Screen Sharing, passwordless sudo, privileged-file permissions, reduced
  Secure Boot). Version-matched CVEs produce one `patch_<cve>` recommendation
  that names the fixed version. Query 100 lists every recommendation with the
  apps or host it applies to and the report prints that list grouped by priority.
- Viewer: an "About" line explains every node kind, each relationship row
  explains what the edge asserts, app dossiers show "Why this score", the
  Computer dossier and the Scope page show host findings and settings that were
  not collected, and recommendation cards show their title, text and priority.
- Collector: new modules `networklisteners` (TCP and UDP listeners from
  `netstat` with pid, process, user and owning app), `trustsettings`
  (certificates in the user and admin trust settings with subject, trust result
  and expiry), `browserextensions` (Chromium-family, Firefox and Safari
  extensions with permissions, site access and install location) and
  `installedpackages` (receipts from `/var/db/receipts`).
- Collector: third-party kernel extensions loaded at scan time are recorded as
  system extensions of type `kernel_extension`.
- Collector: host security settings (guest account, automatic login, root
  account, Remote Apple Events, Remote Management, Software Update options,
  XProtect, XProtect Remediator and MRT versions) and network configuration
  (DNS servers, search domains, enabled proxies, non-default `/etc/hosts`
  entries) are collected with the host posture.
- Collector: Remote Login records `sshd_config` facts (`permit_root_login`,
  password and public-key authentication), the number of authorized keys and
  whether agent forwarding is configured; key material is never recorded.
- Collector: applications record the resolved main executable, its SHA-256 for
  third-party apps, and the host they were downloaded from (quarantine origin
  host only, never the full URL).
- Collector: launch items record their arguments, environment variable names,
  `DYLD_*` environment, launch triggers, interval, session type, disabled and
  loaded state, whether the program exists, its SHA-256, the plist modification
  time and, for items embedded in an app bundle, the bundle path. Items in
  `Contents/Library/LaunchAgents`, `LaunchDaemons` and `LoginItems` of
  installed apps and LoginHook/LogoutHook entries (`login_hook`) are collected.
- Collector: running processes record their parent process id (`ppid`).
- Graph: new node labels `Process`, `NetworkListener`, `TrustedCertificate`,
  `BrowserExtension` and `InstalledPackage` with `INSTANCE_OF`, `PARENT_OF`,
  `RUNS_ON`, `LISTENS_ON`, `EXPOSED_ON`, `TRUSTS_CERTIFICATE`,
  `SAME_CERTIFICATE`, `HAS_EXTENSION` and `INSTALLED_BY` relationships; host
  settings and network configuration are properties of the Computer node.
- Graph: installed apps and the macOS release are matched against NVD by exact
  CPE (`rootstock-graph-cve-enrichment --fetch --scan-json`, or
  `pipeline.sh --refresh-cve`), re-checked client-side and cached offline in
  `~/.rootstock/cache/nvd-installed.json`; `NVD_API_KEY` is optional and
  `--list-cpe-targets` shows catalogue coverage. Matches are `AFFECTED_BY`
  edges with `match_tier: 'cpe'` beside the curated registry's `precise`
  matches (DD-012).
- Graph: queries 104-118 cover installed-software and macOS CVEs, listeners by
  exposure, custom root certificates, risky browser extensions, launchd `DYLD_*`
  injection, stale and user-writable persistence, app-embedded helpers, loaded
  state, recent packages, processes from user-writable locations, the
  process-to-listener map, host security settings and DNS, proxy and hosts-file
  configuration.
- Graph: host posture weighs account, remote-control and Software Update
  settings, custom root certificates, listeners reachable while the firewall is
  off, proxy and hosts-file overrides, and macOS CVEs; application risk adds
  exposed listeners and NVD matches, with new categories
  `launchd_env_injection`, `stale_persistence`, `network_exposed` and
  `browser_extension_risk` and matching recommendations.
- Report: an "Installed Software Vulnerabilities (NVD)" section with the match
  basis per row, and "Network Exposure", "Trust Store", "Browser Extensions",
  "Persistence Detail", "Host Security Settings" and "Processes" sections; the
  executive summary counts NVD matches, macOS CVEs, exposed listeners, custom
  root CAs, risky extensions and `DYLD_*` launch items (or says "not collected"),
  and the scan metadata counts processes, listeners, trusted certificates,
  extensions and packages when `--scan-json` is given.
- Viewer: the Scope page offers questions 104, 106-111 and 117, each answered
  offline from the loaded snapshot with the same columns as the packaged query;
  dossiers show the key facts of each new kind, the Computer's host settings
  ("Not collected" when unread) and launch item detail with `DYLD_*`
  environment highlighted; `AFFECTED_BY` rows name the registry or NVD match;
  the snapshot summary adds host settings, listeners, trust store, extensions,
  packages and NVD counts; the demo includes one synthetic example of each.
- Collector: the scan records the Mac's hardware UUID (`hardware_uuid`, from
  `ioreg`). The graph replaces an earlier scan of the same hostname only when
  the hardware UUID also matches (or neither scan has one); a hostname
  collision between two Macs is reported and both scans are kept.

### Changed

- Graph: reference CVEs matched only by exposure category are now
  `HAS_CVE_CONTEXT` edges (background for a technique class) instead of
  `AFFECTED_BY`. Only version-matched CVEs count as evidence for risk scores,
  tiers, the vulnerability queries and the report; the threat-group queries
  (92, 94) separate confirmed matches from technique context.
- Graph: attack categories are app-specific. A keytab on the host, a user's own
  writable shell profile, an unsandboxed app, or any entitlement no longer put
  every app into `kerberos`, `file_acl_escalation`, `sandbox_escape`,
  `icloud_risk` or `sip_bypass`; `tcc_bypass` and `blastpass_class` remain CVE
  context only.
- Graph: risk scores combine an exposure term (how code gets into the app:
  injection method, signature, notarization, quarantine) with a value term
  (what it gains: grants, keychain trust, root persistence, matched CVEs). A
  hardened app keeps only part of its value term, and a score of 0 is
  `informational`.
- Graph: importing a host again replaces its earlier scans by default so
  findings appear once; `--keep-previous-scans` keeps history side by side and
  `--replace-host` is accepted as a no-op.
- Graph: `LaunchItem` nodes are keyed by `item_key` (`<type>:<path>:<label>`)
  and `XPC_Service` nodes by plist `path` instead of `label`, so two plists that
  share a label stay separate. Run `rootstock-graph-setup-schema` and import into
  a fresh database, or delete the old label-keyed nodes (DD-013).
- Collector: the SQLite reader moved from the `TCC` target into a shared
  `SQLiteSupport` target, also used for the quarantine events database.
- Graph: the snapshot export uses the scanned hostname (not a scan-id prefix),
  carries collection timestamps and coverage, and names Computer, Recommendation,
  Vulnerability, Technique, Firewall, remote access and session nodes instead of
  "Unknown".
- Collector: file writability is judged against the expected owner. A user's
  own dotfiles, launch agents and login keychain are no longer "writable by
  non-root"; world-writable, group-writable (non-root groups) and ACL grants, or
  privileged files owned by a regular user, are.

### Fixed

- Collector: launch item arguments are recorded with secret-looking values
  redacted (values after password/token/key flags, `key=value` secrets, URL
  credentials and query strings, long hex or base64 runs); program hashes and
  existence checks apply to absolute paths only; `BundleProgram` and
  `CFBundleExecutable` values that would leave their bundle are ignored; the
  Electron fuse scan, the BTM database and firewall app plists use bounded,
  regular-file reads; symlinked bundle and browser-profile directories are
  skipped; proxy auto-configuration URLs are stored without credentials or
  query strings.
- Collector: `sshd_config` is parsed the way sshd reads it (first directive
  wins, `Include` files in order, `Match` blocks excluded and flagged).
- Graph: launch items are linked to apps by label only when the shorter name
  has at least three components, and such links carry `confidence:
  'heuristic'`; EPSS/KEV cache entries are validated and non-finite scores
  rejected; the enrichment cache is written atomically with owner-only
  permissions.
- Collector: the firewall state is read from `socketfilterfw` (the ALF plist no
  longer exists on macOS 15+), so enabled, stealth mode, automatic-allow rules
  and per-app rules are collected instead of all unknown.
- Collector: an `spctl` failure no longer records an app as "not notarized";
  only an explicit rejection does, and other failures leave the status unknown
  with a diagnostic. `BYPASSED_GATEKEEPER` and queries 88/89 require observed
  values and ignore unknowns.
- Collector: `codesign` is invoked with `--entitlements - --xml` instead of the
  deprecated `:-` form.
- Graph: `collection_error_sources` on the Computer node is deduplicated with
  counts.
- Graph: macOS-level CVEs compare against the host version parsed from the
  collector's `Version 27.0 (Build …)` string; previously the unparsed string
  made every macOS CVE "conservatively" affect every host (for example Terminal
  CVE-2023-32364 on macOS 27).

### Changed (interface)

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
