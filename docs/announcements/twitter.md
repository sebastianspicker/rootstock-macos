# Twitter/X Announcement

## Short Version (280 chars)
Introducing Rootstock - graph-based attack path discovery for macOS. 23 collector modules, 101 Cypher queries, 17 inference engines. CVE enrichment, risk scoring, BloodHound integration. Think BloodHound for macOS. Open source (GPLv3). github.com/sebastianspicker/rootstock

## Thread Version

1/ Introducing Rootstock - an open-source tool that maps macOS security boundaries as a graph to discover privilege escalation paths automatically.

2/ The collector has 23 data source modules and scans your Mac in <1 second (~185 apps). Extracts TCC grants, entitlements, code signing, XPC services, persistence, Keychain ACLs, MDM profiles, AD bindings, Kerberos artifacts, sandbox profiles, and more.

3/ Data imports into Neo4j across 31 node types. 17 inference engines compute attack relationships: injectable apps, Electron TCC inheritance, shortest paths to FDA, composite risk scores (0-100), and automated remediation recommendations.

4/ Ships with 101 pre-built Cypher queries for Red Team (attack paths), Blue Team (audit), and Forensic (investigation) use cases. REST API with interactive graph viewer. Scan diffing tracks security posture changes.

5/ CVE/EPSS/KEV vulnerability enrichment, ATT&CK technique + ThreatGroup mapping, and bidirectional BloodHound integration. Import SharpHound data, export OpenGraph format.

6/ 751 tests across collector and graph pipeline. Built for the macOS security research community. GPLv3. Zero network calls. Metadata only. Contributions welcome. github.com/sebastianspicker/rootstock
