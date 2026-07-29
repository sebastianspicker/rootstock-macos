# Rootstock Cypher Queries

These queries surface attack paths in the Rootstock Neo4j graph. Run them with the
`query_runner.py` CLI, in the Neo4j Browser (`http://localhost:7474`), or via `cypher-shell`.

## Prerequisites

Before running queries:
```bash
# From the repository root:
NEO4J_AUTH=neo4j/CHANGE_ME docker compose -f graph/docker-compose.yml up -d
NEO4J_PASSWORD=CHANGE_ME uv run --project graph --locked \
  bash graph/pipeline.sh scan.json --skip-report
```

---

## Quick Start (CLI)

```bash
# List all 103 queries with category and severity
uv run --project graph --locked python graph/query_runner.py --list

# Run a single query
uv run --project graph --locked python graph/query_runner.py --run 01

# Run with a parameter
uv run --project graph --locked python graph/query_runner.py --run 17 --param min_permissions=5

# Run all queries and export CSV
uv run --project graph --locked python graph/query_runner.py --run all --format csv > results.csv
```

---

## Query Index

### Red Team - Injection & Escalation

| # | Name | Severity | Description |
|---|------|----------|-------------|
| 01 | Injectable Full Disk Access Apps | Critical | Apps with FDA and modeled injection relationships |
| 02 | Shortest Attack Path to Full Disk Access | Critical | Minimum modeled hops from the synthetic attacker node to FDA |
| 03 | Electron App TCC Permission Inheritance | High | Modeled Electron child-process TCC inheritance |
| 04 | Private Apple Entitlement Audit | High | Third-party apps with private Apple entitlements |
| 05 | Apple Event TCC Permission Cascade | High | Modeled transitive relationships through Apple Event automation |
| 06 | Multi-hop Injection Chain | Critical | Modeled injection chains leading to TCC permission nodes |
| 11 | Multi-hop Injection + Apple Event Privilege Escalation | Critical | Modeled injection and Apple Event relationships to FDA |
| 12 | TCC Database Write Preconditions | Critical | FDA and injection relationships requiring TCC database validation |
| 13 | Keychain Credential Access via Injection | Critical | Modeled injection paths to apps named in Keychain ACL metadata |
| 14 | Persistent Root Code Execution via Injectable Apps | Critical | Apps with injection relationships and associated root LaunchDaemons |
| 15 | XPC Service Privilege Escalation | High | XPC entitlement and communication relationships requiring validation |
| 24 | Admin Group Privilege Escalation | High | Admin-group membership and app injection conditions for review |
| 25 | Remote Access Attack Surface | High | Enabled remote access co-occurring with modeled injection conditions |
| 27 | Unsandboxed Injectable Apps | High | Injectable apps not sandboxed - higher severity injection targets |
| 28 | Firewall-Exposed Injectable Apps | High | Injectable apps with firewall allowing inbound connections |
| 29 | Hijackable Launch Daemons | Critical | Root LaunchDaemons whose binary is writable by non-root users |
| 30 | XPC Services Without SMAuthorizedClients Metadata | High | Services requiring review of their actual client authorization controls |
| 31 | Transitive FDA via Apple Events / Finder Automation | Critical | Modeled Finder automation relationships to Full Disk Access |
| 32 | Active Sessions on Injectable Apps | High | Users with active sessions who have injectable apps with TCC grants |
| 36 | Sudoers NOPASSWD Rules | High | Sudoers rules allowing password-less privilege escalation |
| 38 | Running Injectable Apps with TCC Grants | Critical | Currently running injectable apps with valuable TCC permissions |
| 40 | Injectable Apps Sharing Keychain Groups | High | Modeled injection and Keychain access-group relationships |
| 41 | Shortest Path from Owned Nodes to Full Disk Access | Critical | From any owned node, shortest path to FDA |
| 42 | Reachable High-Value Assets from Owned Nodes | Critical | Modeled TCC, Keychain, and XPC reachability within N hops |
| 43 | User-Centric Access Enumeration | High | Modeled group, session, sudo, application, TCC, and Keychain relationships |
| 44 | All Inbound Paths to Target Asset | Critical | Modeled inbound paths from owned nodes to a target bundle ID |
| 45 | Owned Node Blast Radius Ranking | Critical | Rank each owned node by count of reachable high-value assets |
| 47 | Shortest Paths from Owned Nodes to Tier 0 Assets | Critical | Shortest modeled paths from owned nodes to Tier 0 applications |
| 49 | File Permission Escalation Chains | Critical | Modeled user write relationships to security-relevant files |
| 50 | Shell Hook Injection Paths | High | Writable shell hooks requiring review for injection or credential exposure |
| 51 | Unconstrained Injectable Applications | Critical | Modeled injection relationships where launch constraints are absent |
| 52 | Cross-Host User Presence | High | User identities present in multiple imported host scans |
| 53 | Cross-Host Injection Chain (SSH + Injectable FDA) | Critical | Modeled SSH, host, injection, and FDA relationships |
| 54 | Accessibility API Abuse | Critical | Modeled injection and Accessibility relationships for validation |
| 55 | Injectable Endpoint Security Framework Clients | Critical | ESF apps with modeled injection conditions |
| 56 | Injectable Network Extension Apps | Critical | Apps with network-extension entitlements and injection conditions |
| 58 | Group-Based Capability Escalation | High | Users with debugger or remote access via group membership |
| 61 | Ad-Hoc Signed Apps with TCC Grants | Critical | Apps signed without real certificate (CS_ADHOC) holding TCC |
| 65 | Bluetooth Attack Surface | High | Imported paired-device and Bluetooth TCC relationships |
| 68 | Injectable Apps with iCloud Sync | High | iCloud entitlement, host state, and injection conditions for review |
| 69 | CloudKit Container Injection | High | CloudKit entitlement and injection conditions for review |
| 70 | iCloud Keychain Sync Exposure | Critical | Keychain ACL, host sync state, and injection conditions for review |
| 71 | Password Change Attack Paths | Critical | Modeled password-change and application relationships |
| 86 | Sandbox Escape Vectors via Mach-Lookup | Critical | Sandboxed apps with mach-lookup exceptions to privileged XPC |
| 89 | Quarantine Review for Apps with TCC Grants | Critical | Missing quarantine/notarization metadata combined with TCC grants |
| 95 | High-Risk Applications | Critical | Applications with graph-native risk_score >= 7.0 |
| 98 | Memory Safety Risk | Critical | Apps affected by memory safety CWEs with injection paths |

### Red Team - Vulnerability & CVE

| # | Name | Severity | Description |
|---|------|----------|-------------|
| 72 | AD-Bound Mac Attack Surface | Critical | AD-bound hosts with injectable apps that can access Kerberos tickets |
| 73 | Kerberos Ticket Access via Injectable Apps | Critical | Modeled app-to-ccache read relationships requiring ticket validation |
| 80 | CVE-Affected Applications | Informational | Imported application and CVE associations |
| 81 | CISA KEV + Full Disk Access Applications | Critical | FDA apps with CISA Known Exploited Vulnerabilities |
| 82 | High-EPSS Injectable Applications | Critical | Injectable apps with high exploitation probability (EPSS > 0.3) |
| 83 | Vulnerability-Enriched Attack Chains | Critical | Attack paths where the target app has known CVE associations |
| 84 | Running Injectable Processes with CVEs | Critical | Currently running, injectable processes with known CVEs |
| 85 | Version-Range-Matched Vulnerabilities | Critical | Applications with version-range CVE matches in the precise tier |
| 92 | APT Group Exposure | Critical | Catalog mappings among groups, techniques, CVEs, and imported applications |

### Blue Team - TCC & Entitlements

| # | Name | Severity | Description |
|---|------|----------|-------------|
| 07 | TCC Grant Overview | Informational | Summary of TCC grants present in the imported graph |
| 10 | MDM-Managed TCC Permissions | Informational | TCC grants represented as managed by MDM profiles |
| 16 | Full TCC Grant Inventory | Informational | Imported TCC grants with service, app, grant method, and timestamp metadata |
| 17 | Over-privileged Applications | High | Apps with more TCC permissions than typical threshold |
| 18 | Unsigned or Unhardened Apps with TCC Grants | High | Apps lacking code signing protections that hold TCC grants |
| 19 | Stale TCC Grants (Orphaned Permissions) | High | TCC grants for apps no longer installed on the system |
| 20 | MDM-Managed vs User-Granted TCC Comparison | Informational | Compliance comparison of MDM vs user-granted TCC permissions |
| 37 | Unnotarized Apps with TCC Grants | High | Apps not notarized by Apple but holding TCC privacy grants |
| 39 | MDM Overgrant to Scripting Interpreters | Critical | MDM profiles granting sensitive TCC to scripting interpreters |

### Blue Team - Infrastructure & Hardening

| # | Name | Severity | Description |
|---|------|----------|-------------|
| 08 | Persistence Audit | High | Third-party launch services running as root or injectable |
| 09 | Keychain ACL Audit | High | Apps named in imported Keychain ACL metadata |
| 26 | SIP-Corrected Injection Audit | Informational | Apps excluded from injection analysis by SIP protection |
| 33 | Weak Authorization Rights | High | Authorization database rights with weakened security settings |
| 34 | Non-Apple Authorization Plugins | High | Third-party SecurityAgent plugin metadata for review |
| 35 | Non-Apple System Extensions | High | Third-party system extensions (network filters, ESF, drivers) |
| 46 | Tier Classification Summary | Informational | Classified Application nodes grouped by tier |
| 48 | Critical File Write Access Audit | Critical | Modeled user write access to security-relevant files |
| 57 | Tier 0 Inbound Control Audit | Critical | Modeled inbound paths to applications classified as Tier 0 |
| 59 | Keychain Item Review | High | Keychain item classifications and imported ACL relationships |
| 62 | Apps Signed by Non-Apple Certificate Authorities | High | Apps whose signing chain terminates at a non-Apple root CA |
| 63 | Certificate Authority Hierarchy | Informational | Imported application and certificate-authority relationships |
| 87 | Sandbox Exception Audit | High | Recorded sandbox network or file exceptions for review |
| 88 | Unquarantined Non-System Applications | High | Non-system apps missing imported quarantine metadata |
| 93 | Temporal Priority Vulnerabilities | High | CVEs ranked by temporal urgency combining CVSS, EPSS, and age decay |
| 97 | CWE Weakness Class Heatmap | High | CWE weakness classes ranked by number of affected applications |
| 99 | ESF Monitoring Gaps | High | Critical ESF event types with no active SystemExtension monitoring |
| 100 | Top Recommendations by Affected App Count | High | Recommendations ranked by number of applicable applications |
| 101 | Application Remediation Plan | Informational | Recommendations associated with a selected bundle ID |
| 102 | cve-scan Vulnerable Exposed Services | High | Imported cve-scan service and web evidence affected by vulnerabilities |
| 103 | cve-scan Remediation Queue | High | Imported cve-scan findings prioritized by remediation context |

### Blue Team - Enterprise (AD/Kerberos)

| # | Name | Severity | Description |
|---|------|----------|-------------|
| 74 | AD Group to Local Admin Mapping | Critical | AD groups mapped to local admin in imported host data |
| 75 | Machine Keytab Exposure | High | Keytab permission and modeled read relationships for validation |
| 76 | AD Users with Injectable FDA Apps | Critical | AD session, FDA, injection, and Kerberos metadata relationships |
| 77 | AD Users in Non-Admin Capability Groups | High | AD users in capability-granting groups (_developer, wheel) |
| 78 | Weak Kerberos Encryption Defaults | High | krb5.conf permitting weak encryption (DES, RC4) |
| 79 | Stale Keytab Detection | Informational | Keytabs not rotated in over 1 year |
| 90 | AD to macOS Identity Map | High | AD users mapped to macOS local users via SAME_IDENTITY |
| 91 | AD Group Transitive macOS Access | Critical | Modeled paths from AD group membership to macOS permission nodes |
| 94 | APT Technique Coverage | Informational | Catalog technique mappings to controls and findings |

### Blue Team - Certificates & Physical

| # | Name | Severity | Description |
|---|------|----------|-------------|
| 60 | Expired Signing Certificates with Active TCC Grants | High | Apps signed with expired certificates holding active permissions |
| 64 | Weak Physical Security Posture | High | Hosts lacking lockdown mode, BT discoverable, no screen lock |
| 66 | Physical + Remote Combined Risk | Critical | Weak physical posture and enabled remote access |
| 67 | Physical Security Overview | Informational | Imported host posture and paired Bluetooth-device metadata |

### Forensic - Risk & Remediation

| # | Name | Severity | Description |
|---|------|----------|-------------|
| 21 | High-Value Target Ranking (Attack Value Score) | Informational | Imported apps ranked by the configured attack-value model |
| 22 | Trust Boundary Map | Informational | Imported and inferred app relationships for team, automation, and XPC data |
| 23 | Full Attack Surface Map | Informational | Modeled injection, Electron inheritance, and Apple Event candidates |
| 96 | Risk Score Distribution | Informational | Histogram of risk levels across all Application nodes |

### Ownership & Tier

| # | Name | Severity | Description |
|---|------|----------|-------------|
| 41 | Shortest Path from Owned Nodes to FDA | Critical | From any owned node, shortest escalation path to FDA |
| 42 | Reachable High-Value Assets from Owned Nodes | Critical | All TCC/keychain/XPC reachable from owned nodes within N hops |
| 44 | All Inbound Paths to Target Asset | Critical | All inbound paths from owned nodes to a target bundle_id |
| 45 | Owned Node Blast Radius Ranking | Critical | Rank each owned node by count of reachable high-value assets |
| 46 | Tier Classification Summary | Informational | Classified Application nodes grouped by tier |
| 47 | Shortest Paths from Owned Nodes to Tier 0 Assets | Critical | Shortest escalation paths from owned to crown jewels |
| 57 | Tier 0 Inbound Control Audit | Critical | All inbound attack paths to Tier 0 assets |

Queries 24--103 are documented in their `.cypher` file headers. Run
`uv run --project graph --locked python graph/query_runner.py --describe <number>`
for details.

---

## Query Details

### 01 - Injectable Full Disk Access Apps

File: `01-injectable-fda-apps.cypher` | Category: Red Team | Severity: Critical

Modeled chain: Injection candidate → inherited FDA access

What it returns: Applications with an allowed Full Disk Access grant and a
modeled injection edge inferred from collected configuration properties.

Interpretation:
- Results are candidates for manual validation, not proof of code execution.
- `injection_methods` contains inference-rule labels, not a confirmed attack technique.
- Runtime protections, signatures, platform status, and data completeness can
  invalidate a modeled edge.

---

### 02 - Shortest Path to Full Disk Access

File: `02-shortest-path-to-fda.cypher` | Category: Red Team | Severity: Critical

Attack chain: `attacker.payload` → [any path] → Full Disk Access `TCC_Permission`

What it finds: The minimum number of hops from an attacker's initial foothold
(represented as the synthetic `attacker.payload` node) to Full Disk Access.

Interpretation:
- `path_length = 2` means inject directly into an FDA-holding app (1-hop escalation).
- `path_length = 4` means inject App A → A automates App B → B has FDA (multi-hop).
- Shorter paths contain fewer modeled relationships. Path length alone does not
  establish severity or exploitability.

Note: No results means the current graph contains no matching path. It is not
evidence that the scanned host has no viable path.

---

### 03 - Electron TCC Inheritance Map

File: `03-electron-tcc-inheritance.cypher` | Category: Red Team | Severity: High

Attack: `ELECTRON_RUN_AS_NODE=1 /path/to/Electron.app/Contents/MacOS/app node-script.js`

What it finds: Electron apps with TCC grants and modeled child-process
inheritance relationships.

Interpretation: Validate the app build, process-start condition, macOS version,
and permission behavior before concluding that a child can be started or can
exercise a parent grant.

---

### 04 - Private Entitlement Audit

File: `04-private-entitlement-audit.cypher` | Category: Red Team | Severity: High

What it finds: Non-system applications that possess private Apple entitlements
(`com.apple.private.*`). Entitlement presence identifies a capability for
review and does not prove that the app can exercise it.

Interpretation: Third-party apps with private entitlements may have explicit
special access. Injectable apps with private entitlements require validation of
the injection precondition and the resulting privilege boundary.

---

### 05 - Apple Event TCC Cascade

File: `05-appleevent-tcc-cascade.cypher` | Category: Red Team | Severity: High

Attack: App A → `CAN_SEND_APPLE_EVENT` → App B → invoke B's privileged action

What it finds: Apps that can send Apple Events to a more-privileged app, gaining
transitive access to that app's TCC permissions without holding them directly.

Interpretation: A result models a path where App A could automate App B after
the relevant injection and Apple Event authorization preconditions are met.
Validate those preconditions and the target action before treating the result as
an escalation path.

---

### 06 - Multi-hop Injection Chain

File: `06-injection-chain.cypher` | Category: Red Team | Severity: Critical

What it finds: Chains where the attacker injects one or more apps in sequence,
ultimately reaching an app with a high-value TCC permission. Depth limited to 3 hops;
increase `[*1..N]` for deeper searches.

---

### 07 - TCC Grant Overview (Blue Team)

File: `07-tcc-grant-overview.cypher` | Category: Blue Team | Severity: Informational

What it finds: Three views of TCC grant data (3 separate Cypher statements):
1. Permission distribution - which permissions are most commonly granted
2. Most-permissioned apps - apps with the widest TCC access
3. Authorization reason - how each grant was established (user, MDM, entitlement)

Note: Contains 3 Cypher statements separated by `;`. Run each block individually
in Neo4j Browser (Ctrl+Enter per block), or use `query_runner.py` (runs first block).

---

### 08 - Persistence Audit

File: `08-persistence-audit.cypher` | Category: Blue Team | Severity: High

What it finds: Third-party LaunchDaemons and LaunchAgents that run as root OR are
associated with an injectable application. A result is a modeled condition that
requires validation of injection, launch, and privilege preconditions.

Interpretation: `runs_as_root=true` plus `app_is_injectable=true` identifies a
modeled condition that needs validation of the injection path, launch context,
and runtime privileges.

---

### 09 - Keychain ACL Audit

File: `09-keychain-acl-audit.cypher` | Category: Blue Team | Severity: High

What it finds: Applications explicitly listed in Keychain item ACLs. A
result identifies an ACL relationship that needs validation against the item
and process identity.

Interpretation: Injectable apps with `CAN_READ_KEYCHAIN` model conditions worth
reviewing. Confirm the injection path, Keychain ACL, and item accessibility
before concluding that credentials can be read.

---

### 10 - MDM-Managed TCC Permissions

File: `10-mdm-managed-tcc.cypher` | Category: Blue Team | Severity: Informational

What it finds: TCC permissions associated with imported MDM configuration
profiles. Validate the effective policy, precedence, and user controls on the
relevant macOS version.

Interpretation: Injectable apps with MDM-granted TCC permissions require review.
Confirm the injection path, grant scope, and the target operation before
concluding that access can be inherited.

---

### 11 - Multi-hop Injection + Apple Event Privilege Escalation

File: `11-multi-hop-injection-chain.cypher` | Category: Red Team | Severity: Critical

Parameters: `$target_service` (default: `kTCCServiceSystemPolicyAllFiles`)

Attack: Inject App A → App A automates App B (Apple Event) → App B has `$target_service`

What it finds: Two-step attack chains combining injection with Apple Event automation.
Broader than query 06 - finds paths where the mid-hop uses automation rather than injection.
Use `--param target_service=kTCCServiceScreenCapture` to hunt different target permissions.

---

### 12 - TCC Database Write Path

File: `12-tcc-db-write-path.cypher` | Category: Red Team | Severity: Critical

Attack model: inject an FDA app, then validate whether a writable TCC database
and the required authorization are present.

What it finds: Injectable apps with Full Disk Access. FDA means write access to
the user-level TCC.db (and with additional escalation, the system-level one).

Interpretation: A result indicates modeled FDA and injection preconditions.
Validate TCC database access, macOS protections, and required authorization
before treating it as a write path.

---

### 13 - Keychain Credential Access via Injection

File: `13-keychain-via-injection.cypher` | Category: Red Team | Severity: Critical

Attack model: inject an app, then validate Keychain ACL access for the relevant
item and process identity.

What it finds: Applications with modeled injection and Keychain ACL
relationships. Requires `keychain_acls` data from the Keychain collector.

Interpretation: A result models an injection path and an ACL relationship.
Validate the actual Keychain item, ACL behavior, process identity, and user
interaction requirements before concluding that a credential is accessible.

---

### 14 - Persistent Root Code Execution via Injectable Apps

File: `14-persistence-as-root.cypher` | Category: Red Team | Severity: Critical

Attack model: an injectable app is associated with a root LaunchDaemon.

What it finds: Apps associated with LaunchDaemons modeled as running as root
where the app also has an injection relationship. Requires `launch_items` data
from the persistence collector.

Interpretation: Results identify modeled persistence and privilege conditions.
Validate the injection path, launch configuration, and runtime privileges before
treating a result as persistent root execution.

---

### 15 - XPC Service Privilege Escalation

File: `15-xpc-privilege-escalation.cypher` | Category: Red Team | Severity: High

Attack: Inject client app → call XPC service → XPC inherits entitlements to caller

What it finds: XPC services with entitlements connected through
`COMMUNICATES_WITH` relationships from applications with modeled injection
conditions. Requires `xpc_services` data from the XPC collector.

---

### 16 - Full TCC Grant Inventory

File: `16-tcc-grant-audit.cypher` | Category: Blue Team | Severity: Informational

Parameters: `$scope` (optional: `user` or `system`, default: all)

What it finds: Imported TCC grant rows with service name, app, bundle ID,
grant type (user/MDM/entitlement), and available timestamp metadata.

Use case: Baseline establishment before a policy change, compliance reporting,
or identifying grants that predate a known security incident.

---

### 17 - Over-privileged Applications

File: `17-overprivileged-apps.cypher` | Category: Blue Team | Severity: High

Parameters: `$min_permissions` (default: `3`) - minimum distinct TCC services to flag

What it finds: Apps holding more TCC permissions than the specified threshold.
Results include the full permission list and injectability status.

Interpretation: High permission counts + injectable = priority remediation target.
Use `--param min_permissions=5` for a tighter filter in large environments.

---

### 18 - Unsigned or Unhardened Apps with TCC Grants

File: `18-unsigned-or-unhardened-with-grants.cypher` | Category: Blue Team | Severity: High

What it finds: Apps that have been granted TCC permissions but lack basic code
signing protections (unsigned, missing hardened runtime, or disabled library validation).

Interpretation: These results combine TCC grants with missing signing or runtime
protections. Review the application provenance and verify injection conditions
before deciding whether to retain or revoke a grant.

---

### 19 - Stale TCC Grants (Orphaned Permissions)

File: `19-stale-tcc-grants.cypher` | Category: Blue Team | Severity: High

What it finds: TCC grants referencing bundle IDs for which no installed Application
node exists in the graph. These are grants for uninstalled apps - leftover attack surface.

Interpretation: A stale grant is evidence for review. Validate the current TCC
record, bundle identity binding, code-signing requirements, and applicable
macOS protections before concluding that a replacement app could use it.

---

### 20 - MDM-Managed vs User-Granted TCC Comparison

File: `20-mdm-vs-user-grants.cypher` | Category: Blue Team | Severity: Informational

What it finds: Side-by-side breakdown of MDM-enforced grants vs user-granted TCC
permissions. Useful for compliance validation: are production grants consistent with
what MDM policy dictates?

---

### 21 - High-Value Target Ranking (Attack Value Score)

File: `21-high-value-targets.cypher` | Category: Forensic | Severity: Informational

What it finds: All applications ranked by weighted attack value score:
- `tcc_count × 10` - base TCC surface (each allowed grant = +10)
- `+ injectability × 50` - injectable process flag (+50 if injectable)
- `+ private_ent_count × 20` - private entitlement bonus (+20 per entitlement)
- `+ keychain_count × 30` - Keychain ACL entries (+30 per item)
- `+ daemon_count × 40` - persistence bonus (+40 per LaunchDaemon)

Use case: Prioritize hardening effort; focus on highest-scored apps first.

---

### 22 - Trust Boundary Map

File: `22-trust-boundary-map.cypher` | Category: Forensic | Severity: Informational

Parameters: `$app_name` (optional) - filter to a single app's trust relationships

What it finds: All trust relationships between applications:
- Same team ID (code-signing trust chain)
- Apple Event automation targets (`CAN_SEND_APPLE_EVENT`)
- XPC communication peers (`COMMUNICATES_WITH`)
- Injection vectors (`CAN_INJECT_INTO`)

Use case: Blast-radius analysis - given one compromised app, what can an attacker reach?

---

### 23 - Full Attack Surface Map

File: `23-full-attack-surface.cypher` | Category: Forensic | Severity: Informational

What it finds: Rows for three modeled relationship branches using `UNION ALL`:
`CAN_INJECT_INTO`, `CHILD_INHERITS_TCC`, and `CAN_SEND_APPLE_EVENT`. It does
not enumerate other graph relationship types.

Use case: Full export for offline analysis, or input to external graph tools.
Pipe to `--format csv` and load into Gephi or similar for visual exploration.

---

## Running Queries

### query_runner.py (recommended)

```bash
# List all queries with category/severity colour coding
uv run --project graph --locked python graph/query_runner.py --list

# Run a specific query (table output)
uv run --project graph --locked python graph/query_runner.py --run 01

# Run with parameters
uv run --project graph --locked python graph/query_runner.py --run 17 --param min_permissions=5
uv run --project graph --locked python graph/query_runner.py --run 11 --param target_service=kTCCServiceScreenCapture

# Output formats
uv run --project graph --locked python graph/query_runner.py --run 21 --format json
uv run --project graph --locked python graph/query_runner.py --run 23 --format csv > attack-surface.csv

# Run all queries
uv run --project graph --locked python graph/query_runner.py --run all

# Custom Neo4j connection
NEO4J_PASSWORD=CHANGE_ME uv run --project graph --locked python graph/query_runner.py \
  --neo4j bolt://localhost:7687 --neo4j-user neo4j --run 01
```

### Neo4j Browser (recommended for visualization)

1. Open `http://localhost:7474`
2. Log in with `neo4j` / the password from `NEO4J_AUTH`
3. Load the Browser Guide: `:play http://localhost:8001/rootstock-guide.html`
4. Apply the GraSS stylesheet from `browser/rootstock-style.grass`
5. Paste a query into the editor (⌘K to clear, ⌘Enter to run)

### cypher-shell (command line)

```bash
# Run a single query file
cat graph/queries/01-injectable-fda-apps.cypher | \
  cypher-shell -u neo4j -p "$NEO4J_PASSWORD" --format plain

# Or pipe via docker
cat graph/queries/01-injectable-fda-apps.cypher | \
  docker exec -i rootstock-neo4j cypher-shell -u neo4j -p "$NEO4J_PASSWORD"
```

---

## Interpreting Zero Results

| Query | Zero results means |
|---|---|
| 01, 12 | No imported node matches the modeled injection and FDA conditions |
| 02 | No modeled path from the attacker node to FDA exists in the imported graph |
| 03 | No imported Electron application matches the TCC conditions |
| 04 | No imported third-party application matches the private-entitlement conditions |
| 05, 11 | No imported Apple Event and TCC cascade matches the query |
| 06 | No modeled multi-hop injection path matches the query |
| 13 | No modeled injection candidate is linked to an imported Keychain ACL entry |
| 14 | No modeled injection candidate is linked to an imported root LaunchDaemon |
| 15 | No modeled injection candidate is linked to an imported privileged XPC service |
| 19 | No stale grant matches the query's installed-application comparison |

A zero-row result is not evidence of a secure host by itself. Confirm collector
coverage, Full Disk Access, import warnings, graph inference completion, and
the query's model scope before interpreting it.
