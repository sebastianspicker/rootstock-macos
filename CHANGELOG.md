# Changelog

## v1.0.0 — Stable Release

First stable release. All 7 development phases complete. Collector, graph pipeline,
inference engines, REST API, and documentation are production-ready.

- 26 Swift modules (23 data source modules) in the collector
- 17 inference engines, 101 Cypher queries, 31 Neo4j node types
- 506 Python tests + 279 Swift tests (785 total)
- Full go-live review: .gitignore hardened, Package.resolved committed for reproducibility,
  documentation inconsistencies resolved, collector version bumped to 1.0.0

## [Unreleased]
- Community file integration (LICENSE, CONTRIBUTING, templates)
- Conference submission preparation

## v0.8.0 — Hardening & Release Alignment

Correctness-first hardening pass across graph identity, collector semantics, and Cypher accuracy.

- Multi-scan graph identity: composite primary keys (`app_key`, `computer_key`, `profile_key`)
  allow multiple scans to coexist in the same Neo4j instance without node collisions
- Thread `scan_id` through all import functions; update Neo4j uniqueness constraints
- `Bool` → `Bool?` for Firewall and RemoteAccess fields that can be genuinely unknown
  (not just false) when data is unreadable; collector and schema updated to match
- Symlink resolution in CodeSigning, ProcessSnapshot, and Quarantine data sources
- Fix `CHILD_INHERITS_TCC` edge direction in risk scoring (was backwards)
- Fix `file_acl_escalation` and `mdm_risk` Cypher traversals to use correct relationship paths
- Fix integration test fixture path; add schema setup to pytest session fixture
- CI: trigger on both `main` and `dev` branches
- **Stats:** 31 node types, 785 test functions (506 Python + 279 Swift)

### Bug Fixes
- Fix risk scoring Cypher: use EXISTS subqueries instead of OPTIONAL MATCH/count pattern, fix tier comparison from string 'T0' to integer 0
- Fix injection method matching from 'DYLD' to 'dyld' (case-sensitive match against actual scan data)
- Fix LaunchItem writability check from `li.writable` to `li.program_writable_by_non_root`/`li.plist_writable_by_non_root`
- Fix CHILD_INHERITS_TCC and BYPASSED_GATEKEEPER edge direction in recommendation matchers
- Fix CAN_INJECT_SHELL recommendation to check User->CriticalFile pattern instead of App->()
- Fix MDM_OVERGRANT recommendation to traverse through TCC_Permission nodes
- Fix Kerberos inference: constrain CAN_READ_KERBEROS edges to apps that actually run as the ccache owner
- Fix sandbox Mach service matching to use list membership instead of substring CONTAINS
- Fix Apple Events automation inference: add confidence label and document Cartesian product approximation
- Fix merge_scans to import AD binding, Kerberos artifacts, and sandbox profiles
- Fix BloodHound ADUser import to use batched UNWIND instead of per-user queries
- Fix duplicate bundle_id handling: discard duplicates instead of just logging
- Fix injectable app count query with coalesce() for null injection_methods
- Fix import_local_to to discover users via LaunchItem, LocalGroup, and LoginSession sources
- Fix CORS: replace invalid wildcard origins with regex pattern
- Fix server _get_hostname null safety for empty scan_id
- Fix Cypher write-detection regex to whitelist additional read-only APOC procedures
- Fix KeychainScanner: replace force-cast with optional binding for SecKeychainItem
- Fix SandboxProfileParser regex to handle one level of nested parentheses in SBPL rules
- Add ordering dependency comment in ScanOrchestrator enrichment merge

## v0.7.0 — SOTA Review & Improvement

Full-repo audit and improvement pass across all subsystems. Extended graph pipeline
from attack path discovery to a quantitative risk intelligence platform.

- Added composite risk scoring engine (0-100 scale) with weighted factors: TCC exposure, injection surface, entitlement danger, CVE presence
- Added CWE weakness nodes linked to applications via vulnerability patterns
- Added ESF event enrichment and monitoring gap analysis (inference + queries)
- Added automated remediation recommendation engine with priority-ranked action items
- Added 7 risk/recommendation Cypher queries (95-101): high-risk apps, risk score distribution, CWE weakness heatmap, memory safety risk, ESF monitoring gaps, top recommendations, app remediation plans
- Systematic quality audit across collector (26 modules), graph pipeline (17 inference engines), and query library (101 queries)
- All subsystems at A-grade quality after review pass
- **Stats:** 31 node types, 751 test functions (479 Python + 272 Swift)

## v0.6.0 — Open-Source Preparation

Repository preparation for public release: documentation, CI/CD, and packaging.

- Added GitHub Actions CI pipeline (Swift build + test, Python test suite)
- Added README with screenshots, BibTeX citation, and usage examples
- Added ARCHITECTURE.md with real-world scan statistics and graph model documentation
- Added THREAT_MODEL.md with assumptions and limitations
- Added COMPARISON.md (Rootstock vs BloodHound)
- Added security hardening for CI configuration
- Prepared public repository structure and release artifacts

## v0.5.0 — Hardening & Testing

Test coverage push, multi-version compatibility, and performance hardening.

- Expanded test suite to 751 test functions across Python and Swift
- Added synthetic TCC.db fixtures for different macOS versions
- Added integration tests: collector JSON to Neo4j import to query validation
- Tested on macOS 14 Sonoma, macOS 15 Sequoia, macOS 16 Tahoe
- Optimized collector scan time (~5 seconds for 184 apps, ~45 MB peak memory)
- Added bounded parallelism (max 8) for Security.framework queries
- Added batched UNWIND imports for Neo4j (10-50x faster than N+1 queries)
- Added JSON Schema validation (Draft 2020-12, 1400+ line schema)
- Added macOS version detection and compatibility matrix

## v0.4.0 — Reporting & Visualization

Reports, interactive exploration, and major query library expansion.

- Added Markdown security report generator with Mermaid diagrams and Graphviz DOT export
- Added FastAPI REST API server with Canvas-based interactive graph viewer
- Added Neo4j Browser integration: guide, stylesheet, saved queries
- Added query runner CLI with table/JSON/CSV output
- Added CVE/ATT&CK/ThreatGroup vulnerability import with version-aware matching
- Added live EPSS/KEV/NVD enrichment with 24-hour caching
- Added BloodHound bidirectional integration: SharpHound ZIP import (ADUser/SAME_IDENTITY) and OpenGraph JSON export
- Added tier classification engine (Tier 0/1/2)
- Added scan diffing and merging tools
- Added owned-node marking for attack path simulation
- Expanded query library to 101 Cypher queries across 6 categories: Red Team, Blue Team, Forensic, Ownership, Vulnerability, Risk
- **Stats:** 101 queries, 17 inference engines

## v0.3.0 — Extended Data Sources

Extended the collector from 7 to 23 modules, covering the full macOS security boundary surface.

- Added Groups module: local groups and user details
- Added RemoteAccess module: SSH, VNC, ARD service detection
- Added Firewall module: application firewall policy and rules
- Added LoginSession module: active login sessions (console, SSH, screen sharing)
- Added AuthorizationDB module: authorization rights database
- Added AuthorizationPlugins module: security agent plugins
- Added SystemExtensions module: network/endpoint security/driver extensions
- Added Sudoers module: NOPASSWD rule extraction
- Added ProcessSnapshot module: running process enumeration
- Added FileACLs module: critical file ACL auditing (TCC.db, sudoers, etc.)
- Added ShellHooks module: shell config injection points (.zshrc, .bashrc)
- Added PhysicalSecurity module: Bluetooth, screen lock, Thunderbolt, FileVault posture
- Added ActiveDirectory module: AD binding detection, user/group discovery
- Added KerberosArtifacts module: ccache, keytab, krb5.conf scanning
- Added Sandbox module: SBPL profile deep parsing
- Added Quarantine module: Gatekeeper quarantine xattr reader
- Added corresponding inference engines: file ACL, group capabilities, shell hooks, sandbox, quarantine, kerberos, accessibility, password, physical security, MDM overgrant, Finder FDA
- **Stats:** 23 collector modules, 30+ Codable data models

## v0.2.0 — Graph Pipeline

Neo4j graph import, relationship inference, and initial attack path discovery.

- Added Pydantic v2 validated JSON-to-Neo4j importer with idempotent MERGE operations
- Added modular import pipeline: core, services, security, enterprise, enrichment
- Added inference engine orchestrator with 3 initial engines: injection, electron inheritance, automation
- Added CAN_INJECT_INTO inference (dyld_insert, missing library validation, dyld entitlement)
- Added CHILD_INHERITS_TCC inference for Electron apps
- Added CAN_SEND_APPLE_EVENT inference for automation abuse chains
- Added 22 pre-built Cypher queries (Red Team, Blue Team, Forensic categories)
- Added query runner CLI with table/JSON/CSV output
- Added Neo4j schema setup with constraints and indices
- Added scan tagging with scan_id and imported_at for temporal comparison
- **Stats:** 22 queries, 3 inference engines, ~5,000 edges on typical scan

## v0.1.0 — Initial Collector

Swift CLI collector for TCC, entitlements, code signing, XPC services, persistence,
Keychain ACLs, and MDM profiles.

- Built Swift Package with DataSource protocol for modular collection
- Added TCC database parser for user-level and system-level TCC.db
- Added app discovery across /Applications, ~/Applications, /System/Applications
- Added entitlement extraction via Security.framework with codesign CLI fallback
- Added code signing analysis: hardened runtime, library validation, team ID, certificate chain
- Added XPC service enumeration from LaunchDaemon/LaunchAgent plists
- Added persistence scanner: LaunchDaemons, LaunchAgents, login items
- Added Keychain ACL metadata reader (metadata only, no secrets)
- Added MDM profile and PPPC policy extraction
- Added JSON export with scan metadata (scan_id, hostname, macOS version, elevation status)
- Added CLI with --output, --verbose, --modules flags
- Added graceful degradation when permissions are insufficient
- Added Electron app detection heuristic
- Added macOS version detection (Sonoma 14, Sequoia 15, Tahoe 16)
- **Stats:** 7 modules, single static binary, ~0.6s scan time for 185 apps
