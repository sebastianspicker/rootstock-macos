# ARCHITECTURE.md — System Architecture

## Overview

Rootstock is a three-stage pipeline:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          macOS Endpoint                                  │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                  Collector (Swift CLI, v1.0.0)                    │   │
│  │                                                                   │   │
│  │  Security Boundaries (23 data source modules):                    │   │
│  │  TCC · Entitlements · CodeSigning · XPC · Keychain · Persistence  │   │
│  │  MDM · Groups · RemoteAccess · Firewall · LoginSession            │   │
│  │  AuthorizationDB · AuthorizationPlugins · SystemExtensions        │   │
│  │  Sudoers · ProcessSnapshot · FileACLs · ShellHooks                │   │
│  │  PhysicalSecurity · ActiveDirectory · KerberosArtifacts           │   │
│  │  Sandbox · Quarantine                                             │   │
│  │                            │                                      │   │
│  │                     ┌──────▼──────┐                               │   │
│  │                     │ JSON Export  │  (scan.json, ~1 MB, <6s)     │   │
│  │                     └──────┬──────┘                               │   │
│  └────────────────────────────┼─────────────────────────────────────┘   │
│                               │                                          │
└───────────────────────────────┼──────────────────────────────────────────┘
                                │  scan.json
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        Analysis Workstation                              │
│                                                                          │
│  ┌──────────────────┐   ┌──────────────┐   ┌───────────────────────┐   │
│  │ Graph Import     │──▶│   Neo4j      │◀──│ CVE/ATT&CK Enrichment  │   │
│  │ (6 import mods)  │   │   Database   │   │ (EPSS/KEV/NVD)        │   │
│  └──────────────────┘   └──────┬───────┘   └───────────────────────┘   │
│                                │                                         │
│  ┌──────────────────────────── │ ───────────────────────────────────┐   │
│  │        Inference Engines (17 modules)                             │   │
│  │  Injection · TCC Inheritance · Apple Events · Accessibility       │   │
│  │  Kerberos · Automation · Finder FDA · ESF Monitoring              │   │
│  │  Risk Scoring (0-100) · Recommendations · Sandbox · Quarantine    │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                │                                         │
│            ┌───────────────────┼───────────────────┐                    │
│            ▼                   ▼                   ▼                    │
│  ┌──────────────────┐ ┌───────────────┐ ┌──────────────────┐            │
│  │ 101 Cypher       │ │ REST API      │ │ Markdown / HTML  │            │
│  │ Queries          │ │ (FastAPI)     │ │ Report           │            │
│  │ (Red/Blue/       │ │ + Interactive │ │ + BloodHound     │            │
│  │  Forensic)       │ │ Graph Viewer  │ │   OpenGraph      │            │
│  └──────────────────┘ └───────────────┘ └──────────────────┘            │
└─────────────────────────────────────────────────────────────────────────┘
```

## Design Principle: Separation of Collection and Analysis

The collector runs on the target macOS endpoint. The analysis runs elsewhere.
This separation is intentional:

- **Security:** The collector has minimal footprint and no network dependencies.
- **Portability:** The JSON output can be analyzed on any machine with Neo4j.
- **Reproducibility:** Scan results are static artifacts that can be shared, compared,
  and version-controlled.
- **Multi-host:** Multiple scans from different endpoints can be ingested into the same
  graph to discover cross-host attack paths (future work).

---

## Component: Collector

### Responsibility
Extract security-relevant metadata from the local macOS system and serialize it as JSON.

### Language & Build
- **Language:** Swift 5.9+
- **Build system:** Swift Package Manager
- **Target:** Single static binary, no runtime dependencies beyond macOS system frameworks
- **Entry point:** `collector/Sources/RootstockCLI/main.swift`

### Module Boundaries

Each data source is an independent module behind a `DataSource` protocol:

```swift
protocol DataSource {
    /// Human-readable name for logging
    var name: String { get }

    /// Whether this source requires elevated privileges
    var requiresElevation: Bool { get }

    /// Collect data. Returns partial results on failure (graceful degradation).
    func collect() async throws -> [GraphNode]
}
```

This abstraction serves three purposes:
1. **Graceful degradation:** If the collector lacks FDA, TCC system DB collection fails
   but everything else still works. Each module reports its own success/failure.
2. **Testability:** Modules can be tested independently with fixture data.
3. **Extensibility:** New data sources (MDM profiles, ESF events, etc.) plug in without
   modifying existing code.

### Data Sources (23 Data Source Modules)

| Module | Data Source | Requires Elevation? |
|--------|-------------|---------------------|
| TCC | User + System TCC.db | System: FDA |
| Entitlements | `codesign` / Security.framework entitlement extraction | No |
| CodeSigning | Hardened runtime, library validation, certificate chain | No |
| XPCServices | XPC service plists and Mach port configurations | No |
| Persistence | LaunchDaemons, LaunchAgents, login items, cron | Partial |
| Keychain | Keychain item ACLs (metadata only, no secrets) | Partial |
| MDM | Installed configuration profiles + PPPC policies | No |
| Groups | Local groups + user details | No |
| RemoteAccess | SSH, VNC, ARD service detection | No |
| Firewall | Application firewall policy and rules | No |
| LoginSession | Active login sessions (console, SSH, screen sharing) | No |
| AuthorizationDB | Authorization rights database | No |
| AuthorizationPlugins | Security agent plugins in `/Library/Security/` | No |
| SystemExtensions | Network/endpoint security/driver extensions | No |
| Sudoers | Sudoers NOPASSWD rules | Yes |
| ProcessSnapshot | Running process enumeration | No |
| FileACLs | Critical file ACL auditing (TCC.db, sudoers, etc.) | No |
| ShellHooks | Shell config injection points (.zshrc, .bashrc) | No |
| PhysicalSecurity | Bluetooth, screen lock, Thunderbolt, FileVault posture | No |
| ActiveDirectory | AD binding detection, user/group discovery | No |
| KerberosArtifacts | ccache, keytab, krb5.conf scanning | No |
| Sandbox | Sandbox SBPL profile deep parsing | No |
| Quarantine | Gatekeeper quarantine xattr reader | No |

---

## Component: Graph Import

### Responsibility
Parse collector JSON, validate it, and create/update nodes and relationships in Neo4j.

### Language & Dependencies
- **Language:** Python 3.10+
- **Dependencies:** `neo4j` (official driver), `pydantic` (validation), `fastapi` + `uvicorn` (API server), `tabulate` (report formatting), `requests` (CVE enrichment), `python-multipart` (file uploads)

### Import Behavior
- **Idempotent:** Re-importing the same scan updates existing nodes (MERGE, not CREATE).
- **Scan-tagged:** Each import is tagged with a scan ID and timestamp, enabling
  comparison of before/after states.
- **Batched UNWIND:** All imports use `UNWIND $batch AS row` for performance (not N+1 individual queries).
- **Pydantic validation:** Collector JSON is validated via Pydantic v2 models with `extra="forbid"` to catch schema drift.
- **Relationship inference:** Some relationships are explicit in the JSON (e.g., app → TCC
  grant). Others are inferred during import (e.g., `CAN_INJECT_INTO` is computed by
  checking whether target app lacks hardened runtime + library validation).

---

## Graph Model

### Node Types

```
Application {
    name: String            // e.g., "iTerm"
    bundle_id: String       // e.g., "com.googlecode.iterm2"
    path: String            // e.g., "/Applications/iTerm.app"
    version: String?
    team_id: String?        // Code signing team identifier
    hardened_runtime: Bool
    library_validation: Bool
    is_electron: Bool       // Heuristic: contains Electron framework
    is_system: Bool         // Located in /System/ or /usr/
    signed: Bool
    scan_id: String         // Which scan produced this node
    is_running: Bool?       // From process snapshot
    is_sandboxed: Bool?     // Has sandbox profile
    sandbox_profile: String? // Sandbox profile path
    has_automation_tcc: Bool?
    injection_methods: [String]  // ["dyld_insert", "electron_env_var", etc.]
    risk_score: Float?      // 0-100 composite risk score
    tier: String?           // "tier_0" | "tier_1" | "tier_2" | "tier_3"
    certificate_authority: String?
    certificate_expiry: String?
    is_notarized: Bool?
    has_sudo_nopasswd: Bool?
    quarantine_origin: String?
    code_directory_hash: String?
}

User {
    name: String
    uid: Int
    is_admin: Bool
    home: String
    type: String            // "local" | "network" | "mobile"
}

TCC_Permission {
    service: String         // e.g., "kTCCServiceSystemPolicyAllFiles"
    display_name: String    // e.g., "Full Disk Access"
    scope: String           // "user" | "system"
}

Keychain_Item {
    label: String           // Metadata only
    kind: String            // "generic_password" | "internet_password" | "certificate" | "key"
    service: String?
    // NO secret values — ever
}

XPC_Service {
    label: String           // e.g., "com.apple.diskarbitrationd"
    path: String            // Path to plist
    program: String         // Executable path
    user: String?           // RunAtLoad user
    type: String            // "daemon" | "agent"
}

Entitlement {
    name: String            // e.g., "com.apple.private.tcc.allow"
    is_private: Bool        // com.apple.private.* prefix
    category: String        // "tcc" | "security" | "sandbox" | "other"
}

LaunchItem {
    label: String
    path: String
    type: String            // "daemon" | "agent" | "login_item"
    program: String
    run_at_load: Bool
}

MDM_Profile {
    identifier: String
    display_name: String
    organization: String?
    install_date: String?
}

Vulnerability {
    cve_id: String          // e.g., "CVE-2024-1234"
    description: String
    severity: String        // "critical" | "high" | "medium" | "low"
    cvss_score: Float?
    epss_score: Float?      // Exploit Prediction Scoring
    in_kev: Bool            // In CISA Known Exploited Vulnerabilities
    published: String?
    affected_versions: String?
}

CWE {
    cwe_id: String          // e.g., "CWE-78"
    name: String
    description: String?
    category: String?       // "memory_safety" | "injection" | "auth" | etc.
}

Recommendation {
    id: String
    title: String
    description: String
    priority: String        // "critical" | "high" | "medium" | "low"
    category: String
    effort: String?         // "quick_win" | "moderate" | "significant"
}

ADUser {
    sam_account_name: String
    distinguished_name: String?
    domain: String
    enabled: Bool
    admin_count: Bool?
}

ThreatGroup {
    name: String            // e.g., "APT28"
    aliases: [String]?
    description: String?
    source: String          // "MITRE ATT&CK"
}

Computer {
    hostname: String
    os: String?
    domain: String?
}

AttackTechnique {
    technique_id: String    // e.g., "T1055"
    name: String
    tactic: String?
    description: String?
}
```

### Relationship Types

```
(Application)-[:HAS_TCC_GRANT {allowed: Bool, auth_reason: String?}]->(TCC_Permission)
(Application)-[:HAS_ENTITLEMENT]->(Entitlement)
(Application)-[:SIGNED_BY {team_id: String}]->(Application)  // Same team
(Application)-[:CAN_INJECT_INTO {method: String}]->(Application)
    // method: "dylib_hijack" | "dyld_insert" | "electron_env" | "missing_library_validation"
(Application)-[:CAN_SEND_APPLE_EVENT]->(Application)
(Application)-[:CHILD_INHERITS_TCC]->(Application)
(Application)-[:CAN_READ_KEYCHAIN]->(Keychain_Item)
(Application)-[:COMMUNICATES_WITH]->(XPC_Service)
(Application)-[:PERSISTS_VIA]->(LaunchItem)
(User)-[:OWNS]->(Application)
(User)-[:HAS_KEYCHAIN]->(Keychain_Item)
(LaunchItem)-[:RUNS_AS]->(User)
(MDM_Profile)-[:CONFIGURES]->(TCC_Permission)  // MDM-managed TCC policies
(Application)-[:HAS_VULNERABILITY]->(Vulnerability)
(Vulnerability)-[:MAPS_TO_CWE]->(CWE)
(Application)-[:HAS_RECOMMENDATION]->(Recommendation)
(AttackTechnique)-[:EXPLOITS]->(Vulnerability)
(ThreatGroup)-[:USES_TECHNIQUE]->(AttackTechnique)
(ADUser)-[:SAME_IDENTITY]->(User)
(Application)-[:MONITORED_BY_ESF {event_types: [String]}]->(ESF_Event)
(Application)-[:HAS_RISK_SCORE {score: Float, factors: Map}]->(RiskAssessment)
```

### Inferred Relationships (computed at import time)

These relationships don't exist in the raw collector JSON but are derived:

| Relationship | Inference Rule |
|---|---|
| `CAN_INJECT_INTO` | Target app has `library_validation = false` AND (`hardened_runtime = false` OR has `com.apple.security.cs.allow-dyld-environment-variables` entitlement) |
| `CHILD_INHERITS_TCC` | Source app is Electron-based AND has TCC grants (children spawned via `ELECTRON_RUN_AS_NODE` inherit parent TCC) |
| `CAN_SEND_APPLE_EVENT` | Source app has `com.apple.private.tcc.allow` with `kTCCServiceAppleEvents` OR has explicit TCC grant for automation |

---

## Collector Output Schema (JSON)

```json
{
    "scan_id": "uuid",
    "timestamp": "ISO-8601",
    "hostname": "string",
    "macos_version": "14.5",
    "collector_version": "1.0.0",
    "elevation": {
        "is_root": false,
        "has_fda": false
    },
    "applications": [ /* Application objects */ ],
    "tcc_grants": [ /* TCC grant objects */ ],
    "xpc_services": [ /* XPC service objects */ ],
    "keychain_acls": [ /* Keychain ACL objects */ ],
    "launch_items": [ /* LaunchItem objects */ ],
    "mdm_profiles": [ /* MDM profile objects */ ],
    "users": [ /* User objects */ ],
    "errors": [ /* Per-module error reports */ ]
}
```

See `collector/schema/scan-result.schema.json` for the full JSON Schema definition (1400+ lines, Draft 2020-12).

---

## Real-World Example

A scan on a typical developer Mac (macOS 26.3 Tahoe, arm64) produces the following graph:

### Scan Statistics

| Metric | Value |
|---|---|
| Applications discovered | 184 |
| Signed applications | 180 (98%) |
| Hardened runtime enabled | 123 (67%) |
| Electron apps | 10 (5%) |
| Entitlements extracted | 3,841 |
| XPC services enumerated | 440 |
| Keychain items (metadata) | 234 |
| Launch items (daemons/agents) | 440 |
| MDM profiles | 1 |
| Injectable applications | 89 (48%) |
| TCC grants | 0 (no FDA — see Note) |
| JSON output size | ~1 MB |
| Scan time | 5.3 seconds |
| Peak memory | ~45 MB |

> **Note:** TCC grants require Full Disk Access on macOS 15+. Without FDA, the TCC module
> returns zero grants. With FDA or root, a typical Mac shows 10–50 TCC grants.

### Graph Size (Estimated with TCC)

A typical graph produced from a 184-app scan with TCC grants would contain:

- **~190 Application nodes** (one per discovered app)
- **~20 TCC_Permission nodes** (unique services like FDA, Camera, Microphone)
- **~200 Entitlement nodes** (unique entitlement names from 3,841 app→entitlement pairs)
- **~440 XPC_Service nodes**
- **~234 Keychain_Item nodes**
- **~440 LaunchItem nodes**
- **~3,841 HAS_ENTITLEMENT edges** (app → entitlement)
- **~30–100 CAN_INJECT_INTO edges** (inferred from missing hardened runtime / library validation)
- **~10 CHILD_INHERITS_TCC edges** (Electron apps with TCC grants)
- **~50 COMMUNICATES_WITH edges** (apps referencing XPC mach services via entitlements)

### Example Attack Path

```
(Slack.app)
  -[:HAS_ENTITLEMENT]-> (com.apple.security.cs.allow-dyld-environment-variables)
  # Slack is Electron-based, has allow-dyld entitlement

(Attacker)
  -[:CAN_INJECT_INTO {method: "dyld_insert"}]-> (Slack.app)
  # Slack lacks library validation, allowing DYLD_INSERT_LIBRARIES injection

(Slack.app)
  -[:HAS_TCC_GRANT {allowed: true}]-> (Microphone)
  # If Slack has microphone access, an injected dylib inherits it
```

This three-hop path shows how a DYLD injection into Slack could inherit its TCC microphone
grant — a real attack pattern that Rootstock surfaces automatically.

---

## Design Decisions

| Decision | Rationale | Reference |
|---|---|---|
| Swift for collector | Single static binary, no runtime deps, direct access to Security.framework and macOS APIs | `docs/design-docs/` |
| DataSource protocol | Graceful degradation (each module fails independently), testability, extensibility | §Component: Collector |
| JSON intermediate format | Portable, human-readable, version-controllable; decouples collection from analysis | §Design Principle |
| PRAGMA-based schema detection | Forward-compatible with future macOS TCC changes; avoids hardcoded column assumptions | `docs/research/tcc-version-diffs.md` |
| MERGE (not CREATE) in Neo4j | Idempotent re-imports; safe to re-scan and re-import without duplicates | §Component: Graph Import |
| Inferred relationships | Cross-boundary attack paths (injection, inheritance) can't be read from a single data source — they emerge from correlating multiple sources | §Inferred Relationships |
| Bounded parallelism (max 8) | Prevents overwhelming Security.framework with concurrent code signing queries | `collector/Sources/Entitlements/EntitlementDataSource.swift` |
| Batched UNWIND imports | All Neo4j imports use `UNWIND $batch` instead of N+1 individual `session.run()` calls — 10-50x faster | `graph/import_vulnerabilities.py`, `graph/utils.py` |
| Pydantic `extra="forbid"` | Typos in collector JSON are caught immediately instead of silently ignored | `graph/models.py` |
| Read-only Cypher validation | Ad-hoc Cypher queries via the API are validated against a keyword blocklist before execution | `graph/utils.py`, `graph/server.py` |
| Offline-first CVE enrichment | Static CVE registry works without network; live EPSS/KEV enrichment is optional with 24h cache | `graph/cve_reference.py`, `graph/cve_enrichment.py` |
| `async let` enrichment | Sandbox and quarantine enrichment run concurrently in the collector via structured concurrency | `collector/Sources/RootstockCLI/ScanOrchestrator.swift` |
