# ROADMAP.md — Rootstock Development Roadmap

> Historical roadmap from first line of code to community release.
> Most roadmap phases are now implemented; current work is a hardening and release-alignment pass.

---

## Overview

```
Phase 1 ── Collector MVP                    [Weeks 1–8]
  1.1  Project Scaffolding & Toolchain
  1.2  TCC Database Parser
  1.3  App Discovery & Entitlement Scanner
  1.4  Code Signing Analysis
  1.5  JSON Export & CLI
  1.6  Collector Integration & Validation

Phase 2 ── Graph Pipeline                   [Weeks 7–12]
  2.1  Neo4j Setup & Schema Definition
  2.2  JSON→Graph Importer
  2.3  Inferred Relationships Engine
  2.4  Killer Queries

Phase 3 ── Extended Collection              [Weeks 11–16]
  3.1  XPC Service Enumeration
  3.2  Persistence Scanner
  3.3  Keychain ACL Metadata
  3.4  MDM Profile Analysis

Phase 4 ── Visualization & UX              [Weeks 15–20]
  4.1  Static Reports (Mermaid/Graphviz)
  4.2  Neo4j Browser Integration
  4.3  Interactive Query Library

Phase 5 ── Hardening & Quality             [Weeks 19–22]
  5.1  Test Coverage & Fixtures
  5.2  Multi-macOS Version Compatibility
  5.3  Performance & Edge Cases
  5.4  Documentation & Academic Preparation

Phase 6 ── Community Release               [Weeks 22–24]
  6.1  Repository Preparation
  6.2  Initial Release
  6.3  Community Feedback Cycle
```

```
Week    1   2   3   4   5   6   7   8   9  10  11  12  13  14  15  16  17  18  19  20  21  22  23  24
Phase 1 ████████████████████████████████
Phase 2                         ████████████████████████
Phase 3                                         ████████████████████████
Phase 4                                                         ████████████████████████
Phase 5                                                                         ████████████████
Phase 6                                                                                 ████████████
```

---

## Phase 1 — Collector MVP

> **Goal:** A Swift CLI binary that exports TCC grants, app entitlements, and code signing
> metadata from a macOS endpoint as valid JSON.
>
> **Why first:** Without accurate data, the graph is worthless. The collector is the
> foundation — and already useful as a standalone tool.

---

### 1.1 Project Scaffolding & Toolchain
**Duration:** 3–5 days
**Dependencies:** Xcode installed, macOS 14+ development machine

**Tasks:**
- [ ] Create Swift Package (`Package.swift`) with targets: `CLI`, `TCC`, `Entitlements`, `CodeSigning`, `Models`, `Export`
- [ ] Define `DataSource` protocol (see ARCHITECTURE.md)
- [ ] Define shared data models as `Codable` structs (`Application`, `TCCGrant`, `EntitlementInfo`, etc.)
- [ ] Minimal CLI skeleton with ArgumentParser: `rootstock-collector --output <path>`
- [ ] Build configuration: release build as static binary without external dependencies
- [ ] `.gitignore`, `.swift-format`, Xcode scheme for Debug/Release
- [ ] First test: binary compiles and outputs `--help`

**Result:** `swift build -c release` produces a working binary that outputs "Hello, Rootstock".

**Exec plan:** `docs/exec-plans/active/1-1-scaffolding.md`

---

### 1.2 TCC Database Parser
**Duration:** 1–2 weeks
**Dependencies:** 1.1 complete

**Tasks:**
- [ ] Write SQLite wrapper (C API via Swift, no external SQLite wrapper)
- [ ] Open user-level TCC.db and parse `access` table
- [ ] Map fields: `service` → display name, `auth_value` → allowed/denied, `auth_reason` → origin (user/MDM/system)
- [ ] System-level TCC.db: attempt with error handling (FDA required)
- [ ] `csreq` blob: extract at minimum the bundle identifier (full decoding optional in Phase 3)
- [ ] Graceful degradation: if DB is unreadable → error in `errors` array, no crash
- [ ] Unit tests with a synthetic TCC.db fixture (self-created SQLite file)

**Result:** `TCCDataSource.collect()` returns an array of `TCCGrant` objects.

**Pitfalls:**
- macOS 15 Sequoia introduced additional access restrictions on the user TCC.db
- The `access` table has changed slightly between macOS versions (columns added)
- SQLite DB may be locked if `tccd` is currently writing → consider WAL mode

**Reference:** `docs/research/tcc-internals.md`

---

### 1.3 App Discovery & Entitlement Scanner
**Duration:** 1–2 weeks
**Dependencies:** 1.1 complete (can run parallel to 1.2)

**Tasks:**
- [ ] App discovery: find all `.app` bundles in:
  - `/Applications/`
  - `~/Applications/`
  - `/System/Applications/`
  - `/opt/homebrew/Caskroom/` (Homebrew Cask, optional)
- [ ] For each bundle: parse `Info.plist` → bundle ID, version, name
- [ ] Extract entitlements via Security.framework (`SecStaticCodeCreateWithPath` → `SecCodeCopySigningInformation` with `kSecCSSigningInformation`)
- [ ] Fallback: parse `codesign -d --entitlements :- <path>` as plist if API access fails
- [ ] Classify entitlements by category (TCC, injection, privilege, sandbox, etc.)
- [ ] Flag security-critical entitlements (`isSecurityCritical`)
- [ ] Electron detection: check whether `Frameworks/Electron Framework.framework` exists
- [ ] Unit tests with a fixture app (self-signed test bundle with known entitlements)

**Result:** `EntitlementDataSource.collect()` returns an array of `Application` objects with entitlements.

**Pitfalls:**
- System apps under `/System/Applications/` on SSV (Signed System Volume) may have
  restricted codesign info
- Some apps have embedded helper tools with their own entitlements (e.g., `Contents/Library/LoginItems/`)
- Homebrew Cask apps exist as symlinks → handle path resolution

**Reference:** `docs/research/entitlements-reference.md`

---

### 1.4 Code Signing Analysis
**Duration:** 1 week
**Dependencies:** 1.3 complete (builds on app discovery)

**Tasks:**
- [ ] For each discovered app: check code signing status
  - `SecStaticCodeCreateWithPath` + `SecCodeCopySigningInformation`
  - Extract team identifier
  - Check hardened runtime flag (`kSecCodeSignatureRuntime`)
  - Check library validation flag
- [ ] `signed: Bool` — is the app signed at all?
- [ ] `is_system: Bool` — located under `/System/` or `/usr/`?
- [ ] Derive injection susceptibility:
  - No hardened runtime → `dyld_insert` possible
  - Hardened runtime BUT `allow-dyld-environment-variables` entitlement → `dyld_insert` possible
  - No library validation → unsigned dylibs loadable
- [ ] Attach this metadata to the `Application` objects from 1.3
- [ ] Unit test: known system app (e.g., Terminal.app) has expected signing properties

**Result:** Every `Application` object has complete code signing metadata.

---

### 1.5 JSON Export & CLI
**Duration:** 3–5 days
**Dependencies:** 1.2, 1.3, 1.4 complete

**Tasks:**
- [ ] Assemble `ScanResult` struct (see schema in ARCHITECTURE.md)
- [ ] Populate metadata: `scan_id` (UUID), `timestamp`, `hostname`, `macos_version`, `collector_version`
- [ ] Detect elevation status: `is_root`, `has_fda` (attempt to open system TCC.db)
- [ ] Orchestrate all `DataSource` modules: collect → merge → serialize
- [ ] JSON output: `JSONEncoder` with `outputFormatting: [.prettyPrinted, .sortedKeys]`
- [ ] Implement CLI flags:
  - `--output <path>` (required)
  - `--verbose` (optional detail output on stderr)
  - `--modules <tcc,entitlements,codesigning>` (optional module selection)
- [ ] Progress display on stderr (which module is running, how many apps scanned)
- [ ] Error reporting: each module reports success/failure in the `errors` array

**Result:** `rootstock-collector --output scan.json` produces a complete JSON file.

---

### 1.6 Collector Integration & Validation
**Duration:** 3–5 days
**Dependencies:** 1.5 complete

**Tasks:**
- [ ] End-to-end test on the development machine
- [ ] Manually validate JSON output:
  - Known TCC grants present? (Terminal has FDA? iTerm has FDA?)
  - Entitlements for known apps correct? (Slack is Electron? Xcode has debugger entitlement?)
  - Code signing metadata plausible? (System apps are signed and hardened?)
- [ ] Performance measurement: how long does a full scan take?
- [ ] Test without elevation: collector runs as normal user without crash
- [ ] Test with `sudo`: system TCC.db is additionally read
- [ ] JSON schema validation (Python script with `jsonschema` against formal schema)
- [ ] Compare scan output on a second machine (if available)
- [ ] Document known issues in `docs/exec-plans/tech-debt-tracker.md`

**Result:** Validated, tested collector — ready for Phase 2.

**Milestone:** M1 — "We have data"

---

## Phase 2 — Graph Pipeline

> **Goal:** Import collector JSON into a Neo4j graph database, infer relationships,
> and discover the first attack paths via Cypher queries.
>
> **Why now:** The raw data from Phase 1 only becomes valuable through the graph.
> This is where we validate whether the data model works and whether real attack paths emerge.

---

### 2.1 Neo4j Setup & Schema Definition
**Duration:** 3–5 days
**Dependencies:** Neo4j installed (Docker recommended)

**Tasks:**
- [ ] `docker-compose.yml` for Neo4j 4.4+ (compatible with BloodHound ecosystem)
- [ ] Define constraints and indices:
  - Unique constraint on `Application.bundle_id`
  - Unique constraint on `TCC_Permission.service`
  - Unique constraint on `Entitlement.name`
  - Index on `Application.hardened_runtime`, `Application.library_validation`
- [ ] Schema documentation in `docs/generated/db-schema.md` (generated from constraints)
- [ ] Pydantic models for JSON validation of collector output
- [ ] Connection test: Python script connects to Neo4j and creates a test node

**Result:** Running Neo4j instance with defined schema.

---

### 2.2 JSON→Graph Importer
**Duration:** 1–2 weeks
**Dependencies:** 2.1 complete, Phase 1 collector output available

**Tasks:**
- [ ] `import.py` — main script: reads JSON, validates, imports
- [ ] Node import in order (due to references):
  1. `User` nodes
  2. `TCC_Permission` nodes (static list of all known services)
  3. `Entitlement` nodes
  4. `Application` nodes
  5. `XPC_Service`, `LaunchItem`, `Keychain_Item`, `MDM_Profile` (Phase 3)
- [ ] Edge import: explicit relationships from the JSON
  - `Application` → `HAS_TCC_GRANT` → `TCC_Permission`
  - `Application` → `HAS_ENTITLEMENT` → `Entitlement`
  - `Application` → `SIGNED_BY` (same team ID cluster)
- [ ] MERGE semantics instead of CREATE (idempotency on re-import)
- [ ] Scan tagging: every node gets `scan_id` and `imported_at` properties
- [ ] Print import statistics: "Imported 247 apps, 89 TCC grants, 1,432 entitlements"
- [ ] Error handling: skip invalid JSON entries, don't abort

**Result:** `python3 import.py --input scan.json --neo4j bolt://localhost:7687` populates the graph.

---

### 2.3 Inferred Relationships Engine
**Duration:** 1–2 weeks
**Dependencies:** 2.2 complete

**Tasks:**
- [ ] `CAN_INJECT_INTO` inference:
  ```
  For each app A with a TCC grant:
    If A.library_validation == false:
      → CAN_INJECT_INTO {method: "missing_library_validation"}
    If A.hardened_runtime == false:
      → CAN_INJECT_INTO {method: "dyld_insert"}
    If A has entitlement "allow-dyld-environment-variables":
      → CAN_INJECT_INTO {method: "dyld_insert_via_entitlement"}
  ```
- [ ] `CHILD_INHERITS_TCC` inference:
  ```
  For each app A where is_electron == true AND A has TCC grants:
    → CHILD_INHERITS_TCC (via ELECTRON_RUN_AS_NODE)
  ```
- [ ] `CAN_SEND_APPLE_EVENT` inference:
  ```
  For each app A with TCC grant for kTCCServiceAppleEvents:
    → CAN_SEND_APPLE_EVENT to the apps for which automation is allowed
  For each app A with entitlement "com.apple.private.tcc.allow" + AppleEvents:
    → CAN_SEND_APPLE_EVENT to all apps
  ```
- [ ] Mark inferred edges with `{inferred: true}` property
- [ ] Statistics: "Inferred 34 CAN_INJECT_INTO, 7 CHILD_INHERITS_TCC edges"
- [ ] Unit tests with minimal graph (3–5 nodes, known expected edges)

**Result:** The graph contains both explicit and inferred relationships.

---

### 2.4 Killer Queries
**Duration:** 1 week
**Dependencies:** 2.3 complete

**Tasks:**
- [ ] **Query 1 — Injectable FDA Apps:**
  Find all apps with Full Disk Access that can be code-injected.
  ```cypher
  MATCH (a:Application)-[:HAS_TCC_GRANT]->(t:TCC_Permission {service: 'kTCCServiceSystemPolicyAllFiles'})
  MATCH (a)-[:CAN_INJECT_INTO]-(injector)
  RETURN a.name, a.path, injector.name, injector.method
  ```

- [ ] **Query 2 — Shortest Path to FDA:**
  From any (non-critical) app to Full Disk Access.
  ```cypher
  MATCH path = shortestPath(
    (start:Application)-[*..5]-(target:TCC_Permission {service: 'kTCCServiceSystemPolicyAllFiles'})
  )
  WHERE NOT (start)-[:HAS_TCC_GRANT]->(target)
  RETURN path, length(path) AS hops
  ORDER BY hops ASC LIMIT 10
  ```

- [ ] **Query 3 — Electron TCC Inheritance:**
  Which Electron apps inherit which permissions?
  ```cypher
  MATCH (e:Application {is_electron: true})-[:HAS_TCC_GRANT]->(t:TCC_Permission)
  RETURN e.name, collect(t.display_name) AS permissions
  ORDER BY size(permissions) DESC
  ```

- [ ] **Query 4 — Private Entitlement Audit:**
  Apps with private Apple entitlements (potential high-value targets).
  ```cypher
  MATCH (a:Application)-[:HAS_ENTITLEMENT]->(e:Entitlement {is_private: true})
  RETURN a.name, collect(e.name) AS private_entitlements
  ORDER BY size(private_entitlements) DESC LIMIT 20
  ```

- [ ] **Query 5 — TCC Grant Cascade via Apple Events:**
  App A can send Apple Events to App B, App B has FDA → transitive access.
  ```cypher
  MATCH (a:Application)-[:CAN_SEND_APPLE_EVENT]->(b:Application)-[:HAS_TCC_GRANT]->(t:TCC_Permission)
  WHERE NOT (a)-[:HAS_TCC_GRANT]->(t)
  RETURN a.name AS sender, b.name AS target, t.display_name AS gained_permission
  ```

- [ ] Save each query as a `.cypher` file in `graph/queries/` with comment header
- [ ] Validate queries against real scan output
- [ ] Document results: "On my machine, Query 1 finds the following paths: …"

**Result:** Five documented queries that reveal real attack paths.

**Milestone:** M2 — "We find attack paths"

---

## Phase 3 — Extended Collection

> **Goal:** Extend the collector with the remaining data sources —
> XPC services, persistence mechanisms, Keychain ACLs, MDM profiles.
>
> **Why now:** The core pipeline works. Each new data source enriches the graph
> and enables new query categories.

---

### 3.1 XPC Service Enumeration
**Duration:** 1–2 weeks
**Dependencies:** Phase 1 collector architecture

**Tasks:**
- [ ] Parse LaunchDaemon plists: `/System/Library/LaunchDaemons/`, `/Library/LaunchDaemons/`
- [ ] Parse LaunchAgent plists: `/Library/LaunchAgents/`, `~/Library/LaunchAgents/`
- [ ] For each service: label, Program/ProgramArguments, MachServices, UserName
- [ ] Extract MachServices entries → these define reachable XPC endpoints
- [ ] Check entitlements of XPC service binaries (recursive: what entitlements does the daemon have?)
- [ ] Implement `XPCDataSource`, extend graph import
- [ ] New edge: `COMMUNICATES_WITH` (App → XPC_Service via MachService name)

**Result:** XPC services in graph, connections to apps visible.

---

### 3.2 Persistence Scanner
**Duration:** 1 week
**Dependencies:** 3.1 (partial, since LaunchDaemons/Agents overlap)

**Tasks:**
- [ ] LaunchDaemons + LaunchAgents (already captured in 3.1) as `LaunchItem` nodes
- [ ] Login Items: `~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`
- [ ] Login Items via SMAppService API (macOS 13+)
- [ ] Cron jobs: `/var/at/tabs/`, `/etc/crontab`
- [ ] New edges: `PERSISTS_VIA` (App → LaunchItem), `RUNS_AS` (LaunchItem → User)

**Result:** All persistence points in graph with assignment to apps and users.

---

### 3.3 Keychain ACL Metadata
**Duration:** 1–2 weeks
**Dependencies:** Phase 1 code signing analysis (for team ID matching)

**Tasks:**
- [ ] Enumerate Keychain items via Security.framework (`SecItemCopyMatching`)
- [ ] Metadata only: label, service, account, access group — **no password values**
- [ ] ACLs per item: which partition IDs, which team IDs have access?
- [ ] Infer: which apps (via team ID) can read which items without a prompt?
- [ ] Implement `KeychainDataSource`
- [ ] New nodes: `Keychain_Item`; new edges: `CAN_READ_KEYCHAIN`

**Pitfalls:**
- Keychain access can trigger user prompts → use metadata-only APIs
- Some Keychain APIs require the login Keychain to be unlocked
- System Keychain requires admin privileges

**Result:** Keychain trust relationships in graph.

---

### 3.4 MDM Profile Analysis
**Duration:** 3–5 days
**Dependencies:** None (standalone module)

**Tasks:**
- [ ] Parse `profiles show -all` output (or `profiles -C -o stdout`)
- [ ] For each profile: identifier, display name, organization, payload content
- [ ] Identify TCC-relevant payloads (Privacy Preferences Policy Control)
- [ ] Implement `MDMDataSource`
- [ ] New nodes: `MDM_Profile`; new edges: `CONFIGURES` (Profile → TCC_Permission)

**Result:** MDM-managed security settings visible in graph.

**Milestone:** M3 — "Complete data collection"

---

## Phase 4 — Visualization & UX

> **Goal:** Make graph data usable for different audiences —
> from automated reports to interactive exploration.

---

### 4.1 Static Reports
**Duration:** 1 week
**Dependencies:** Phase 2 killer queries

**Tasks:**
- [ ] Python script: runs all killer queries and generates a Markdown report
- [ ] Report sections: executive summary, injectable FDA apps, TCC grant overview,
  Electron apps with inheritance, recommendations
- [ ] Optional: Mermaid diagrams for the most important attack paths inline in report
- [ ] Optional: Graphviz DOT export for more complex paths
- [ ] `rootstock-report --neo4j bolt://localhost:7687 --output report.md`

**Result:** A Markdown report that can be embedded in pentest reports or academic papers.

---

### 4.2 Neo4j Browser Integration
**Duration:** 1 week
**Dependencies:** Phase 2 graph pipeline

**Tasks:**
- [ ] Create Neo4j Browser guides (`:play rootstock`)
- [ ] Provide curated queries as saved queries in Neo4j Browser
- [ ] Node styling: colors by type (apps=blue, TCC=red, entitlements=yellow, etc.)
- [ ] Graph style sheet for Neo4j Browser (`grass` format)
- [ ] Documentation: "Getting Started with Rootstock in Neo4j Browser"

**Result:** Neo4j Browser displays Rootstock data in a visually appealing and navigable way.

---

### 4.3 Interactive Query Library
**Duration:** 1–2 weeks
**Dependencies:** 4.2 complete

**Tasks:**
- [ ] Expand query library: 15–20 prebuilt queries for typical scenarios
- [ ] Categorization: Red Team (attack paths), Blue Team (audit), forensics
- [ ] Parameterized queries: `$target_service`, `$app_name`, etc.
- [ ] README for query library with description and example output per query
- [ ] Optional: simple CLI tool that makes queries interactively selectable

**Result:** Documented query collection covering red team, blue team, and forensic use cases.

**Milestone:** M4 — "Usable by third parties"

---

## Phase 5 — Hardening & Quality

> **Goal:** Bring the project to the standard required for academic
> publication and community release.

---

### 5.1 Test Coverage & Fixtures
**Duration:** 1–2 weeks
**Dependencies:** Phase 1–3 modules implemented

**Tasks:**
- [ ] Create synthetic TCC.db fixtures for different scenarios
- [ ] Build fixture apps (self-signed, with/without hardened runtime, Electron dummy)
- [ ] Unit tests per collector module with fixtures
- [ ] Integration test: collector → JSON → import → query → expected result
- [ ] Graph tests: known input → expected nodes/edges/paths
- [ ] CI configuration (GitHub Actions, macOS runner for Swift tests)

---

### 5.2 Multi-macOS Version Compatibility
**Duration:** 1 week
**Dependencies:** Access to different macOS versions (VMs or hardware)

**Tasks:**
- [ ] Test on macOS 14 Sonoma, macOS 15 Sequoia (minimum)
- [ ] Document TCC schema differences
- [ ] Encapsulate version-specific code paths behind abstractions
- [ ] Maintain compatibility matrix in README

---

### 5.3 Performance & Edge Cases
**Duration:** 3–5 days

**Tasks:**
- [ ] Benchmark: how long does a scan take with 200+ installed apps?
- [ ] Measure memory usage and optimize if needed (streaming instead of all in RAM)
- [ ] Edge cases: apps without bundle ID, corrupted signatures, empty Keychains
- [ ] Test large JSON files: import performance into Neo4j
- [ ] Evaluate parallelization (collect from multiple DataSources concurrently)

---

### 5.4 Documentation & Academic Preparation
**Duration:** 1–2 weeks

**Tasks:**
- [ ] Finalize README with screenshots/example output
- [ ] Enrich ARCHITECTURE.md with real examples
- [ ] Document threat model: assumptions, limitations, what Rootstock CANNOT do
- [ ] Comparison with BloodHound: similarities, differences, complementary usage
- [ ] Academic paper skeleton (if planned): abstract, related work, methodology
- [ ] Maintain BibTeX entry

**Milestone:** M5 — "Publication-ready"

---

## Phase 6 — Community Release

> **Goal:** Make the project public and gather initial community feedback.

---

### 6.1 Repository Preparation
**Duration:** 3–5 days

**Tasks:**
- [ ] Create GitHub repository under suitable organization
- [ ] LICENSE (GPLv3), CONTRIBUTING.md, CODE_OF_CONDUCT.md
- [ ] GitHub issue templates: bug report, feature request, new data source
- [ ] GitHub Actions: build check, lint, test
- [ ] Check for sensitive data: no real scan outputs in the repo
- [ ] Build release binary (Universal Binary for Intel + Apple Silicon)

---

### 6.2 Initial Release
**Duration:** 1 week

**Tasks:**
- [ ] Set v0.1.0 tag and create GitHub release
- [ ] Prepare announcement for:
  - Twitter/X (macOS security community: @objective_see, @its_a_feature_, etc.)
  - Reddit (r/netsec, r/macsysadmin)
  - Objective by the Sea Slack/Discord (if available)
  - BloodHound community (SpecterOps Discord)
- [ ] Blog post on university page or GitHub Pages
- [ ] Optional: demo video (5 min: scan → import → query → attack path found)

---

### 6.3 Community Feedback Cycle
**Duration:** ongoing

**Tasks:**
- [ ] Triage and prioritize issues
- [ ] Implement quick wins (merge 1–2 community contributions)
- [ ] Gather feedback on graph model (missing nodes/edges?)
- [ ] Evaluate BloodHound OpenGraph integration (Rootstock data in BloodHound CE?)
- [ ] Prepare conference submission (Objective by the Sea, BSides, etc.)

**Milestone:** M6 — "Living open-source project"

---

## Phase 7 — Graph Intelligence Maturation

> **Goal:** Extend the graph pipeline from attack path discovery to a full
> risk intelligence platform with quantitative scoring, weakness taxonomy,
> and actionable recommendations.

### 7.1 Risk Scoring Engine
- [x] Composite risk score per Application (0-100 scale)
- [x] Weighted factors: TCC exposure, injection surface, entitlement danger, CVE presence
- [x] 7 new Cypher queries (95-101) for risk analysis

### 7.2 CWE Weakness Taxonomy
- [x] CWE nodes linked to Applications via vulnerability patterns
- [x] Weakness heatmap query for systemic risk identification

### 7.3 ESF Event Enrichment
- [x] Endpoint Security Framework monitoring gap analysis
- [x] ESF event type correlation with Application capabilities

### 7.4 Recommendation Engine
- [x] Automated remediation recommendations per Application
- [x] Priority-ranked action items based on risk score

**Milestone:** M7 — "Quantitative risk intelligence"

---

## Milestone Overview

| Milestone | Description | Criterion |
|---|---|---|
| **M1** | We have data | Collector produces valid JSON with TCC + entitlements + code signing |
| **M2** | We find attack paths | 5 killer queries return real results on real scan |
| **M3** | Complete data collection | XPC, persistence, Keychain, MDM in graph |
| **M4** | Usable by third parties | Reports, Neo4j UI, query library, documentation |
| **M5** | Publication-ready | Tests, compatibility, academic documentation |
| **M6** | Living open-source project | Public release, community feedback, first external contributions |
| **M7** | Quantitative risk intelligence | Risk scoring, CWE taxonomy, ESF enrichment, recommendation engine |

---

## Decision Points

At these points, a conscious decision must be made before continuing:

| Timing | Decision | Options |
|---|---|---|
| After M1 | Security.framework vs. CLI parsing | API-only, CLI fallback, or hybrid? |
| After M2 | BloodHound OpenGraph integration | Own UI vs. Rootstock as OpenGraph plugin? |
| After M2 | Academic publication | Paper yes/no? If yes: which conference/journal? |
| After M3 | Live analysis (processes) | Add process node or static analysis only? |
| After M4 | Multi-host support | Single Neo4j instance for multiple Macs? Merge strategy? |
