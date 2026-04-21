# Rootstock: Graph-Based Attack Path Discovery for macOS Security Boundaries

> Structured outline for a potential conference paper submission.
> Sections marked with [DATA] require results from evaluation scans.

## Abstract (200 words)

- **Problem:** macOS security boundaries — TCC grants, code signing entitlements, Keychain ACLs, XPC trust relationships — create complex, invisible trust relationships between applications. Unlike Active Directory environments (where BloodHound enables systematic attack path discovery), no equivalent tool exists for macOS-native security mechanisms.
- **Approach:** We present Rootstock, an open-source tool that models macOS security boundaries as a directed property graph. Rootstock collects metadata from eight data sources (TCC databases, code signing, entitlements, XPC services, Keychain ACLs, persistence mechanisms, MDM profiles) and imports them into Neo4j, where pre-built Cypher queries automatically discover privilege escalation paths.
- **Results:** On [N] macOS systems running macOS 14–26, Rootstock discovered [M] potential attack paths across [K] categories, including DYLD injection into FDA-holding apps, Electron child process TCC inheritance, and XPC service abuse. A typical 184-app scan completes in under 6 seconds.
- **Contribution:** Rootstock is the first systematic, graph-based tool for macOS-native attack path analysis. It is open-source, extensible, and designed for integration with existing tools like BloodHound.

## 1. Introduction

- Growing macOS adoption in enterprise environments (cite: Jamf/Mosyle market data)
- Complexity of the macOS security model: TCC, SIP, Gatekeeper, Keychain, entitlements, notarization — each with separate trust boundaries
- Gap: BloodHound transformed AD attack path analysis; no macOS equivalent exists
- Existing macOS offensive tools (Bifrost, Chainbreaker, SwiftBelt) are point solutions — they extract individual data sources but don't model relationships between them
- Our contribution:
  1. A formal graph model for macOS security boundaries (8 node types, 13 relationship types)
  2. An open-source collector that extracts security metadata from macOS endpoints
  3. A query library of 23 pre-built attack path queries organized by severity
  4. Empirical evaluation on real-world macOS systems

## 2. Background

### 2.1 macOS Security Architecture

- **TCC (Transparency, Consent, and Control):** Per-app permission grants for camera, microphone, Full Disk Access, etc. Stored in SQLite databases at user and system level. Kernel-enforced on macOS 15+.
- **Code Signing & Hardened Runtime:** Apps signed with team identifiers; hardened runtime restricts DYLD injection; library validation prevents unsigned dylib loading.
- **Entitlements:** XML-embedded privileges requested by apps at signing time. Private entitlements (com.apple.private.*) grant elevated access.
- **SIP (System Integrity Protection):** Kernel-level protection for system files and processes.
- **Keychain:** Credential storage with per-item ACLs controlling which apps can access which secrets.
- **XPC Services:** Inter-process communication via Mach ports; launchd-managed daemons and agents.
- **MDM (Mobile Device Management):** Enterprise profiles that can pre-authorize TCC grants.

### 2.2 Attack Path Analysis & Graph Theory in Security

- BloodHound (Robbins et al., 2016): graph-based AD attack path discovery
- BloodHound CE and BHOPG (OpenGraph) architecture
- Graph theory in security: shortest-path privilege escalation, centrality analysis for high-value targets
- MITRE ATT&CK macOS matrix: technique coverage mapping

### 2.3 Existing macOS Offensive Tools

- **Bifrost** (Cody Thomas): Kerberos interaction on macOS
- **Chainbreaker** (n0fate): Keychain database extraction
- **SwiftBelt** (Cedric Owens): macOS enumeration in Swift
- **TCC.db readers:** Various scripts and tools for reading TCC databases
- **Limitation of point solutions:** Each extracts one data source; none model cross-boundary relationships

## 3. Design & Implementation

### 3.1 Graph Model

- Node types: Application, TCC_Permission, Entitlement, XPC_Service, Keychain_Item, LaunchItem, MDM_Profile, User
- Explicit relationships: HAS_TCC_GRANT, HAS_ENTITLEMENT, SIGNED_BY_SAME_TEAM, CAN_READ_KEYCHAIN, COMMUNICATES_WITH, PERSISTS_VIA, RUNS_AS, CONFIGURES
- Inferred relationships: CAN_INJECT_INTO, CHILD_INHERITS_TCC, CAN_SEND_APPLE_EVENT
- Inference rules and their security semantics
- Figure: graph schema diagram

### 3.2 Data Collection

- Collector architecture: Swift CLI, DataSource protocol, 8 modules
- Data source details: TCC (SQLite, PRAGMA-based schema detection), Entitlements (Security.framework + codesign CLI), CodeSigning (SecStaticCode API), XPC (launchd plist parsing), Keychain (SecItemCopyMatching), Persistence (LaunchDaemons/Agents/crontab), MDM (profiles CLI)
- macOS version compatibility: PRAGMA table_info for forward-compatible TCC schema detection
- Parallelization: TaskGroup with bounded concurrency (8 concurrent app scans)
- Privacy by design: no secrets extracted, no network calls

### 3.3 Analysis Engine

- Neo4j graph database with UNWIND-batched import (idempotent MERGE semantics)
- Relationship inference engine (Python): CAN_INJECT_INTO, CHILD_INHERITS_TCC, CAN_SEND_APPLE_EVENT
- Query library: 23 pre-built Cypher queries across 4 severity levels (critical, high, medium, info)
- Query categories: injectable FDA apps, Electron TCC inheritance, private entitlement analysis, XPC service trust, Keychain ACL exposure

## 4. Evaluation

### 4.1 Methodology

- [DATA] Number of macOS systems scanned (version distribution: Sonoma, Sequoia, Tahoe)
- Scan conditions: user-level (no FDA) and root-level (with FDA) for comparison
- Enterprise vs. personal Mac configurations
- Reproducibility: open-source tool, fixture-based tests, documented methodology

### 4.2 Attack Paths Discovered

- [DATA] Categories and counts of attack paths found
- **Category 1: Injectable FDA apps** — Apps with Full Disk Access that lack hardened runtime or library validation, enabling DYLD injection to inherit their TCC grants
- **Category 2: Electron TCC inheritance** — Electron apps with TCC grants whose child processes (spawned via ELECTRON_RUN_AS_NODE) inherit the parent's TCC context
- **Category 3: Private entitlement exposure** — Apps with com.apple.private.* entitlements that bypass normal TCC prompts
- **Category 4: XPC privilege escalation** — User-level applications that communicate with root-level XPC services via Mach ports
- [DATA] Case studies: representative attack paths with severity assessment

### 4.3 Performance

- Scan time: 5.64s average on 184-app Mac (macOS 26.3 Tahoe, arm64)
- Per-module timing: TCC 0.00s, Entitlements 0.15s, CodeSigning 0.21s, XPC 4.83s, Persistence 0.01s, Keychain 0.06s, MDM 0.02s
- Peak memory: ~45 MB
- JSON output size: ~1 MB for 184 apps
- Graph import: UNWIND-batched, completes in seconds for 200+ apps
- Comparison: manual enumeration of the same data sources would take hours

### 4.4 Comparison with Manual Analysis

- Time comparison: Rootstock scan (seconds) vs. manual enumeration (hours)
- Completeness: Rootstock models relationships that manual analysis typically misses
- Accuracy: discuss false positives (SIP-protected apps appearing injectable) and false negatives (attack paths not modeled)

## 5. Discussion

### 5.1 Limitations

- SIP false positives in injection assessment (TD-006)
- TCC access restrictions on macOS 15+ (FDA required)
- Inferred relationships are necessary conditions, not sufficient for exploitation
- Single-host analysis (no fleet-wide correlation automated yet)
- No runtime behavioral analysis

### 5.2 Ethical Considerations

- Responsible disclosure: findings reported to vendors before publication
- Authorized use only: tool requires local access to the system being analyzed
- Data sensitivity: scan output contains security-relevant metadata; handling guidelines provided
- Dual-use awareness: the same attack paths visible to defenders are visible to attackers

### 5.3 Future Work

- BloodHound OpenGraph integration for unified AD + macOS analysis
- Live analysis via Endpoint Security Framework (Process nodes, real-time edges)
- Multi-host correlation and fleet-wide attack surface mapping
- macOS Sequoia/Tahoe-specific security mechanism modeling
- CI/CD integration for automated security baseline checks

## 6. Related Work

- BloodHound and SharpHound (Robbins et al., 2016; SpecterOps)
- Bifrost (Thomas, 2020) — Kerberos on macOS
- Chainbreaker (n0fate, 2014) — Keychain extraction
- SwiftBelt (Owens, 2019) — macOS enumeration
- Patrick Wardle's macOS security research (Objective-See)
- Wojciech Regula's macOS TCC research
- Csaba Fitzl's TCC bypass research
- Apple Platform Security Guide (Apple, 2024)
- MITRE ATT&CK for macOS
- Enterprise macOS security (Jamf, Mosyle research)

## 7. Conclusion & Future Work

- Summary of contributions: graph model, collector, query library, evaluation
- Key finding: macOS security boundaries create exploitable relationships invisible without graph analysis
- Rootstock fills the BloodHound-shaped gap for macOS-native security
- Open-source availability and community contribution model
- Future directions: BloodHound integration, ESF live analysis, fleet correlation
