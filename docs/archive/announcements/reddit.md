# Reddit Announcement

## r/netsec

**Title:** Rootstock: Graph-based attack path discovery for macOS (open source)

**Body:**

I've been working on Rootstock, an open-source tool that maps macOS security boundaries into a Neo4j graph to discover privilege escalation paths automatically.

**What it does:**
- Swift CLI collector with 23 data source modules extracts TCC grants, entitlements, code signing metadata, XPC services, persistence mechanisms, Keychain ACLs, MDM profiles, Active Directory bindings, Kerberos artifacts, sandbox profiles, sudoers rules, file ACLs, and more from a macOS endpoint
- Python pipeline imports everything into Neo4j across 31 node types, then 17 inference engines compute attack relationships (injectable apps, Electron TCC inheritance, Apple Event cascades, composite risk scores, remediation recommendations)
- 101 pre-built Cypher queries find real attack paths (shortest path to FDA, injectable privileged apps, multi-hop injection chains)
- CVE/EPSS/KEV vulnerability enrichment with ATT&CK technique and ThreatGroup mapping
- BloodHound bidirectional integration — import SharpHound data, export OpenGraph format
- REST API with interactive graph viewer and scan diffing for change detection
- Think BloodHound, but for macOS-native security boundaries

**Key findings on a test system:**
- 112 apps injectable via missing library validation, dyld insert, or Electron env vars
- 10 Electron apps that pass TCC permissions to child processes
- 6,000+ Apple Event automation edges enabling transitive TCC access

**Technical details:**
- Collector: Swift, 23 modules, single binary, no deps, <1 second scan time for ~185 apps
- Graph: Neo4j 5.x, Pydantic validation, MERGE-based idempotent import, 17 inference engines
- 751 tests, macOS 14-16 compatibility

GPLv3. No network calls. Metadata only.

GitHub: [link]

Feedback welcome, especially from macOS red teamers and enterprise security teams.

## r/macsysadmin

**Title:** Rootstock: Open-source tool to audit TCC grants, entitlements, and security config on your Mac fleet

Similar body but emphasize Blue Team queries, MDM profile analysis, fleet-wide audit capabilities, Active Directory + Kerberos integration, composite risk scoring, automated remediation recommendations, and scan diffing for tracking security posture changes across your fleet.
