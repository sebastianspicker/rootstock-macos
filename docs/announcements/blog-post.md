# Introducing Rootstock: Graph-Based Attack Path Discovery for macOS

## The Problem

macOS has a rich set of security boundaries: TCC (Transparency, Consent, and Control) gates
access to the camera, microphone, and files. Code signing and hardened runtime prevent code
injection. Entitlements grant specific capabilities to specific apps.

But these boundaries interact in complex ways. An Electron app with Screen Recording
permission can be exploited via `ELECTRON_RUN_AS_NODE` to spawn a child process that
inherits those permissions. An app missing library validation can be injected with a
malicious dylib to hijack its TCC grants. Apple Event automation creates transitive trust
chains across app boundaries.

Finding these attack paths manually is tedious. You'd need to cross-reference TCC databases,
entitlement plists, code signing flags, and XPC service configurations — then reason about
how they chain together. That's exactly what graph databases excel at.

## What Rootstock Does

Rootstock is a three-stage pipeline:

1. **Collect** — A Swift CLI with 23 data source modules scans the local Mac in under
   1 second, extracting TCC grants, app entitlements, code signing metadata, XPC services,
   persistence mechanisms, Keychain ACLs, MDM profiles, Active Directory bindings, Kerberos
   artifacts, sandbox profiles, sudoers rules, firewall policies, file ACLs, shell hooks,
   system extensions, authorization database rights, and more. Output: structured JSON.

2. **Import & Infer** — A Python pipeline validates the JSON and imports it into Neo4j
   across 31 node types. Then 17 inference engines compute attack relationships — injection
   paths, TCC inheritance, automation cascades, composite risk scores (0-100), and automated
   remediation recommendations.

3. **Query & Analyze** — 101 pre-built Cypher queries discover real attack paths, from simple
   (injectable FDA apps) to complex (multi-hop injection chains via Apple Event automation).
   A REST API with an interactive graph viewer lets you explore results visually, and scan
   diffing tracks how your security posture changes over time.

## What We Found

On a standard developer Mac with ~185 installed apps:

- **112 injectable apps** — missing library validation, no hardened runtime, or Electron-based
- **10 Electron apps** passing TCC permissions to child processes via ELECTRON_RUN_AS_NODE
- **6,000+ Apple Event automation edges** creating transitive trust relationships
- **994 unique entitlements** across all apps, including private Apple entitlements on
  non-system apps

## Get Started

```bash
# Build the collector
cd collector && swift build -c release

# Scan your Mac
.build/release/rootstock-collector --output scan.json

# Start Neo4j and import
cd graph && docker compose up -d
python3 setup.py && python3 import.py --input ../scan.json
python3 infer.py

# Find attack paths
python3 query_runner.py --run 03  # Electron TCC inheritance
python3 report.py --output report.md  # Full security report
```

## Beyond Discovery: Vulnerability Enrichment & Enterprise Integration

Rootstock goes beyond static graph analysis:

- **CVE/EPSS/KEV vulnerability enrichment** — Automatically matches installed applications
  against known CVEs, enriched with EPSS exploit probability scores and CISA KEV status
  for prioritization.
- **ATT&CK technique + ThreatGroup mapping** — Links discovered attack paths to MITRE
  ATT&CK techniques and known threat groups that exploit them.
- **BloodHound bidirectional integration** — Import SharpHound data to bridge Active
  Directory attack paths with macOS-native security boundaries. Export Rootstock graphs
  in OpenGraph format for BloodHound consumption.
- **Composite risk scoring** — Every node receives a 0-100 risk score combining
  exploitability, exposure, and privilege level.
- **Automated remediation recommendations** — Actionable fix suggestions for every
  discovered vulnerability.
- **Enterprise support** — Active Directory binding analysis, Kerberos artifact discovery,
  sandbox profile deep parsing, and MDM/PPPC policy extraction.

## Open Source

Rootstock is GPLv3 with 751 tests across the collector and graph pipeline. It makes zero
network calls, extracts no secrets, and runs with minimal privileges. Contributions
welcome — especially new data sources, queries, and testing on diverse macOS configurations.

GitHub: [link]
