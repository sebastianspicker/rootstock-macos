# rootstock

[![Build](https://github.com/sebastianspicker/rootstock/actions/workflows/test.yml/badge.svg)](https://github.com/sebastianspicker/rootstock/actions)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![macOS 14+](https://img.shields.io/badge/macOS-14%2B-brightgreen)](https://support.apple.com/macos)
[![Version](https://img.shields.io/badge/version-1.0.0-blue)](CHANGELOG.md)

Attack path discovery for macOS that maps TCC grants, entitlements, Keychain ACLs, and XPC trust relationships as an exploitable graph.

## What is Rootstock?

Rootstock is a graph-based attack path discovery tool for macOS security boundaries — think BloodHound for macOS-native trust relationships. It maps:

- **TCC grants** — which apps have camera, microphone, full disk access, etc.
- **Entitlements** — code-signing privileges that weaken security boundaries
- **Code signing** — hardened runtime, library validation, team identifiers, certificate chain analysis
- **Injection vectors** — per-app assessment of DYLD injection viability
- **Vulnerability correlation** — CVE/EPSS/KEV enrichment with ATT&CK technique mapping
- **Risk scoring** — composite 0-100 risk score per application with tier classification
- **Enterprise integration** — Active Directory binding, Kerberos artifacts, BloodHound interop
- **ESF monitoring** — Endpoint Security Framework event coverage gap analysis

## Project Map

Rootstock has three deliberate parts plus one checked-in demo fixture:

1. `collector/` is the endpoint-side Swift package. It reads local macOS
   security metadata and emits one portable scan JSON. It should stay passive:
   no network calls, no secrets, and recoverable per-module errors instead of
   aborting the whole scan.
2. `modules/cve-scan/` is the Rootstock CVE evidence module. It is a
   dependency-light Python CLI for scoped infrastructure/package/web evidence
   and writes `scan.json` plus `rootstock-export.json` artifacts for graph
   import. It is not a competing vulnerability-management platform.
3. `graph/` is the workstation-side Python package. `graph/pipeline.sh` is the
   normal orchestration path: apply Neo4j schema, optionally refresh cached CVE
   data, import the scan, run inference, classify tiers, and write a report or
   start the API server. It can also import a prebuilt cve-scan artifact with
   `--cve-scan-export`.
4. `examples/demo-scan.json` is the demo fixture source of truth.
   `examples/regenerate.sh` rebuilds local generated report/viewer artifacts
   from that fixture; it does not modify the fixture.

The contract between the halves is the scan JSON. When changing collector
output, keep `collector/schema/scan-result.schema.json`, `graph/models.py`, and
the importer code in sync, then validate with:

```bash
python3 scripts/validate-scan.py <scan.json>
```

## Screenshots

The static screenshots below use synthetic demo data from [demo-scan.json](examples/demo-scan.json).

### Interactive Graph Viewer

| | |
|---|---|
| ![Full Graph](docs/screenshots/01-full-graph.png) | ![Attack Path](docs/screenshots/02-attack-path.png) |
| *Full attack graph — node types color-coded by kind* | *Shortest path from attacker to Full Disk Access (2 hops)* |
| ![Node Inspector](docs/screenshots/03-node-inspector.png) | ![Electron TCC](docs/screenshots/04-electron-inheritance.png) |
| *iTerm2 property inspector with risk score, tier, and entitlements* | *Slack's inherited TCC permissions via focus mode* |

### Security Report

| | |
|---|---|
| ![Summary](docs/screenshots/05-report-summary.png) | ![Attack Diagram](docs/screenshots/06-attack-path-diagram.png) |
| *Executive summary with critical findings and scan metadata* | *Mermaid attack path flowcharts (injectable FDA + Apple Events)* |
| ![CVE Table](docs/screenshots/07-cve-table.png) | ![Tier Classification](docs/screenshots/08-tier-pie.png) |
| *CVE reference with CVSS/EPSS scores and ATT&CK mapping* | *Tier classification — Tier 0 through Tier 3 with risk scores* |

### Collector CLI

![CLI Output](docs/screenshots/09-cli-output.png)

*Collector module timing output*

### Demo Outputs

| Output | Description |
|--------|-------------|
| [`demo-scan.json`](examples/demo-scan.json) | Synthetic scan data used by the docs and demo pipeline |

> To generate report and viewer outputs (requires Neo4j): `bash examples/regenerate.sh`
> This produces `examples/generated/demo-report.md` and `examples/generated/demo-viewer.html` locally.

The synthetic cve-scan graph fixture is [examples/cve-scan-export.json](examples/cve-scan-export.json).
See [the cve-scan module guide](docs/guides/cve-scan-module.md) and the module
[example outcome](modules/cve-scan/docs/example-outcome.md) for the artifact
shape without publishing real infrastructure data.

<details>
<summary>Mermaid diagrams (GitHub-rendered fallback)</summary>

#### Injectable App to Full Disk Access

```mermaid
graph LR
    A["Attacker<br/>(local user)"] -->|DYLD_INSERT_LIBRARIES| B["iTerm2<br/>injectable, no lib validation"]
    B -->|inherits TCC grant| C["Full Disk Access<br/>kTCCServiceSystemPolicyAllFiles"]
    C -->|read/write| D["TCC.db<br/>system + user databases"]
    C -->|read| E["Keychain metadata<br/>ACLs, trusted apps"]

    style A fill:#e74c3c,color:#fff
    style B fill:#e67e22,color:#fff
    style C fill:#c0392b,color:#fff
    style D fill:#8e44ad,color:#fff
    style E fill:#8e44ad,color:#fff
```

#### Electron TCC Inheritance

```mermaid
graph LR
    A["Attacker"] -->|ELECTRON_RUN_AS_NODE| B["Slack<br/>Electron, injectable"]
    B -->|inherits| C["Camera"]
    B -->|inherits| D["Microphone"]
    B -->|inherits| E["Screen Recording"]

    style A fill:#e74c3c,color:#fff
    style B fill:#e67e22,color:#fff
    style C fill:#2ecc71,color:#fff
    style D fill:#2ecc71,color:#fff
    style E fill:#2ecc71,color:#fff
```

#### Transitive FDA via Finder Automation

```mermaid
graph LR
    A["OmniGraffle<br/>injectable, Apple Events TCC"] -->|automates| B["Finder<br/>SIP-protected, implicit FDA"]
    B -->|has| C["Full Disk Access"]

    style A fill:#e67e22,color:#fff
    style B fill:#3498db,color:#fff
    style C fill:#c0392b,color:#fff
```

#### Asset Tier Classification

```mermaid
pie title Asset Tier Distribution
    "Tier 0 — Crown Jewels" : 3
    "Tier 1 — High Value" : 4
    "Tier 2 — Standard" : 5
    "Tier 3 — Low Privilege" : 3
```

</details>

## Quick Start

### Requirements

**Collector** (runs on the Mac being scanned):
- macOS 14 (Sonoma) or later
- Swift 5.9+ (Xcode 15+)

**Graph pipeline** (runs on analysis workstation):
- Python 3.10+
- Neo4j 5.0+ (Docker recommended: `docker run -p7474:7474 -p7687:7687 neo4j:5`)

### Build

```bash
cd collector
swift build -c release
```

### Run

```bash
# Full scan (TCC + entitlements + code signing)
.build/release/rootstock-collector --output scan.json

# Verbose progress output
.build/release/rootstock-collector --output scan.json --verbose

# TCC grants only
.build/release/rootstock-collector --output scan.json --modules tcc

# Entitlements + code signing only (no TCC)
.build/release/rootstock-collector --output scan.json --modules entitlements,codesigning

# With Full Disk Access (reads system TCC.db)
sudo .build/release/rootstock-collector --output scan.json
```

### Validate Output

```bash
pip3 install -r graph/requirements.txt
python3 scripts/validate-scan.py scan.json
# ✓ Valid: scan.json (184 apps, 12 TCC grants, 3841 entitlements, 0 collection errors)
```

### Example Output

```json
{
  "scan_id": "7D7DFA2B-...",
  "timestamp": "2026-03-18T08:00:00Z",
  "hostname": "my-mac.local",
  "macos_version": "Version 15.0 (Build 26A...",
  "collector_version": "0.1.0",
  "elevation": {
    "is_root": false,
    "has_fda": false
  },
  "applications": [
    {
      "name": "1Password",
      "bundle_id": "com.1password.1password",
      "path": "/Applications/1Password.app",
      "version": "8.10.56",
      "team_id": "2BUA8C4S2C",
      "hardened_runtime": true,
      "library_validation": true,
      "is_electron": true,
      "is_system": false,
      "signed": true,
      "entitlements": [
        {
          "name": "com.apple.security.cs.allow-jit",
          "is_private": false,
          "category": "injection",
          "is_security_critical": true
        }
      ],
      "injection_methods": ["electron_env_var"]
    }
  ],
  "tcc_grants": [],
  "errors": []
}
```

### Graph Pipeline

```bash
# Install Python dependencies
pip3 install -r graph/requirements.txt

# Start Neo4j with the bundled local compose file
cd graph && NEO4J_AUTH=neo4j/CHANGE_ME docker compose up -d && cd ..

# Run the full pipeline (schema -> import -> infer -> classify -> report)
NEO4J_PASSWORD=CHANGE_ME bash graph/pipeline.sh scan.json

# Import a prebuilt cve-scan Rootstock artifact during the same pipeline run
NEO4J_PASSWORD=CHANGE_ME bash graph/pipeline.sh scan.json \
  --cve-scan-export modules/cve-scan/runs/local/rootstock-export.json

# Or start the API server with interactive viewer
ROOTSTOCK_API_TOKEN=CHANGE_ME_API_TOKEN NEO4J_PASSWORD=CHANGE_ME \
  bash graph/pipeline.sh scan.json --serve 8000
# Open http://localhost:8000 for the interactive graph viewer
```

Environment variables for Neo4j connection: `NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASSWORD`.
The live API additionally requires `ROOTSTOCK_API_TOKEN`. CVE network refresh is
opt-in with `--refresh-cve`; the default pipeline uses cached/static enrichment.

## Local Verification

```bash
# Swift collector
(cd collector && swift test --parallel)

# Python graph pipeline
ruff check graph/ scripts/ examples/ docs/
(cd graph && pytest tests)

# cve-scan module
(cd modules/cve-scan && ruff check . && pytest)
shellcheck modules/cve-scan/scripts/perf-smoke.sh

# Shell entry points
shellcheck examples/regenerate.sh graph/pipeline.sh scripts/*.sh tests/integration/*.sh

# Cross-language scan contract
python3 scripts/validate-scan.py examples/demo-scan.json
```

Runtime smoke tests need Neo4j. With `graph/docker-compose.yml`, set
`NEO4J_AUTH=neo4j/CHANGE_ME` and use the matching `NEO4J_PASSWORD`.

## Feature Matrix

| Category | Scope | Details |
|----------|-------|---------|
| Collector modules | Swift data-source modules | TCC, entitlements, code signing, XPC, persistence, keychain, MDM, groups, remote access, firewall, login sessions, authorization DB/plugins, system extensions, sudoers, processes, file ACLs, shell hooks, physical security, AD, Kerberos, sandbox, quarantine |
| Graph node types | Typed graph model | Application, TCC_Permission, Entitlement, User, XPC_Service, LaunchItem, Keychain_Item, MDM_Profile, Computer, Vulnerability, CWE, AttackTechnique, ThreatGroup, ADUser, Recommendation, and more |
| Inference engines | Inference pipeline | Injection assessment, TCC inheritance, Apple Events, accessibility, Kerberos, automation, Finder FDA, ESF monitoring, risk scoring, recommendations, and more |
| Cypher queries | Query library | Red Team, Blue Team, and forensic workflows |
| Python tests | pytest suite | Unit tests, integration tests, edge case coverage |
| API surface | REST API | OpenAPI docs, interactive viewer, Cypher console |
| CVE registry | Curated static registry | macOS-focused CVEs with EPSS/KEV/NVD live enrichment |

## Performance

Benchmarked on macOS 26.3 Tahoe (arm64), 184 apps, release build:

| Metric | Value |
|--------|-------|
| Total scan time | 5.6 seconds (average of 3 runs) |
| Apps scanned | 184 |
| Entitlements extracted | 3,841 |
| XPC services enumerated | 440 |
| Keychain items | 234 |
| Peak memory | ~45 MB |
| JSON output size | ~1 MB |

Per-module timing (via `--verbose`):

```
[TCC]          0.00s   [Entitlements] 0.15s   [CodeSigning]  0.21s
[XPC]          4.83s   [Persistence]  0.01s   [Keychain]     0.06s
[MDM]          0.02s   Total: 5.28s
```

See `docs/benchmarks/baseline.md` for full benchmark methodology and results.

## macOS Compatibility

| macOS Version | Collector | User TCC.db | System TCC.db | Notes |
|---|---|---|---|---|
| 14 Sonoma | ✅ Full | ✅ Normal read | ✅ Requires FDA | Primary development target |
| 15 Sequoia | ✅ Full | ⚠️ Requires FDA | ✅ Requires FDA | Kernel-enforced; grant FDA or use sudo |
| 26 Tahoe | ✅ Full | ⚠️ Requires FDA | ✅ Requires FDA | Year-based versioning (2025 release) — tested on 26.3 |
| < 14 | ❌ | ❌ | ❌ | Not supported |

> **Apple switched to year-based macOS versioning in 2025.** macOS 26 ("Tahoe") was formerly planned as "macOS 16". `ProcessInfo.majorVersion` returns 26 on Tahoe.

## Notes on TCC Collection

macOS 15+ requires Full Disk Access to read TCC databases. Without FDA:
- User TCC.db: blocked at kernel level (`SQLITE_AUTH`)
- System TCC.db: blocked at kernel level

Run with `sudo` or grant FDA to the binary to collect TCC grants. See `docs/research/tcc-version-diffs.md` for full details; the historical tech-debt note is archived at `docs/archive/exec-plans/tech-debt-tracker.md` as TD-004.

## Project Structure

```
collector/                 Swift CLI collector
├── Sources/
│   ├── Models/            Shared data models + MacOSVersion detection
│   ├── TCC/               TCC database parser with PRAGMA schema validation
│   ├── Entitlements/      App discovery + entitlement extraction (parallelized)
│   ├── CodeSigning/       Code signing analysis + injection assessment
│   ├── XPCServices/       XPC service enumeration
│   ├── Keychain/          Keychain ACL metadata reader
│   ├── Persistence/       LaunchDaemons/Agents/crontab scanner
│   ├── MDM/               MDM configuration profile parser
│   ├── Groups/            Local groups + user details
│   ├── RemoteAccess/      SSH, VNC, ARD service detection
│   ├── Firewall/          Application firewall policy
│   ├── LoginSession/      Active login sessions
│   ├── AuthorizationDB/   Authorization rights database
│   ├── AuthorizationPlugins/ Security agent plugins
│   ├── SystemExtensions/  System/network extensions
│   ├── Sudoers/           Sudoers NOPASSWD rules
│   ├── ProcessSnapshot/   Running process enumeration
│   ├── FileACLs/          Critical file ACL auditing
│   ├── ShellHooks/        Shell config injection points
│   ├── PhysicalSecurity/  Bluetooth, screen lock, Thunderbolt posture
│   ├── ActiveDirectory/   AD binding + user/group discovery
│   ├── KerberosArtifacts/ ccache, keytab, krb5.conf
│   ├── Sandbox/           Sandbox profile deep parsing (SBPL rules)
│   ├── Quarantine/        Gatekeeper quarantine xattr reader
│   ├── Export/            JSON serialization
│   └── RootstockCLI/      CLI entry point + scan orchestration
├── Tests/                 Unit tests
└── schema/                JSON Schema for output validation

graph/                     Neo4j import, inference, query engine & API
├── import.py              Scan JSON → Neo4j importer (orchestrator)
├── import_cve_scan.py     cve-scan rootstock-export.json → Neo4j importer
├── import_nodes_core.py   Core node imports (apps, TCC, entitlements, certs)
├── import_nodes_services.py   Services (XPC, persistence, keychain)
├── import_nodes_security.py   Security nodes (groups, firewall, auth, sudoers)
├── import_nodes_security_enterprise.py  Enterprise (AD, Kerberos, process, file ACL)
├── import_nodes_enrichment.py Enrichment (physical, iCloud, bluetooth)
├── import_vulnerabilities.py  CVE/ATT&CK/ThreatGroup import + version matching
├── infer.py               Inference engine orchestrator
├── infer_esf.py           ESF event enrichment + monitoring gap analysis
├── infer_risk_score.py    Composite risk scoring engine (0-100 scale)
├── infer_recommendations.py  Automated remediation recommendations
├── server.py              FastAPI REST API server
├── models.py              Pydantic v2 graph node/edge type definitions
├── setup_schema.py        Neo4j schema constraints and indices
├── constants.py           Shared constants and configuration
├── tier_classification.py Asset tier classification engine
├── cve_reference.py       CVE + ATT&CK + ThreatGroup registry
├── cve_enrichment.py      Live EPSS + KEV + NVD enrichment with caching
├── version_matcher.py     Version-aware CVE matching
├── bloodhound_import.py   SharpHound ZIP → ADUser/SAME_IDENTITY import
├── opengraph_export.py    BloodHound OpenGraph JSON export
├── report.py              Markdown report generator
├── report_assembly.py     Report section assembly + orchestration
├── report_formatters.py   Report output formatters (MD, HTML, JSON)
├── viewer_template.html   Interactive Canvas-based graph viewer
├── pipeline.sh            One-command pipeline (schema → import → infer → classify → report)
├── queries/               Pre-built Cypher queries
└── tests/                 Python tests

scripts/
├── validate-scan.py       Output validation script
└── benchmark.sh           Performance benchmark runner

modules/
└── cve-scan/              Scoped CVE evidence CLI and Rootstock export bridge

docs/
├── THREAT_MODEL.md        Assumptions, limitations, ethical framework
├── design-docs/           Architecture decisions (AD/Kerberos, risk scoring, vuln intel, etc.)
├── references/            Entitlement categories, macOS security reference
├── benchmarks/            Performance measurements
├── research/              macOS security research notes
├── screenshots/           README and report screenshots
└── archive/               Historical planning, announcement, paper, and product-spec material

deprecated/                Historical scripts kept out of the active workflow
```

## Threat Model

Rootstock is a passive, read-only analysis tool. It does not extract secrets, make network
calls, or execute attacks. See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the full
threat model, including assumptions, limitations, BloodHound comparison, and ethical framework.

## Citing Rootstock

```bibtex
@software{rootstock2026,
  title   = {Rootstock: Graph-Based Attack Path Discovery for macOS Security Boundaries},
  author  = {Sebastian J. Spicker},
  year    = {2026},
  url     = {https://github.com/sebastianspicker/rootstock},
  note    = {Open-source research tool, Cologne University of Music}
}
```
