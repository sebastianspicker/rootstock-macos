# Rootstock Cypher Queries

These queries surface attack paths in the Rootstock Neo4j graph. Run them with the
`query_runner.py` CLI, in the Neo4j Browser (`http://localhost:7474`), or via `cypher-shell`.

## Prerequisites

Before running queries:
```bash
cd graph
docker compose up -d          # start Neo4j
python3 setup.py              # initialize schema + seed TCC nodes
python3 import.py --input scan.json  # import collector data
python3 infer.py              # compute inferred relationships
```

---

## Quick Start (CLI)

```bash
# List all 101 queries with category and severity
python3 query_runner.py --list

# Run a single query
python3 query_runner.py --run 01

# Run with a parameter
python3 query_runner.py --run 17 --param min_permissions=5

# Run all queries and export CSV
python3 query_runner.py --run all --format csv > results.csv
```

---

## Query Index

### Red Team — Injection & Escalation

| # | Name | Severity | Description |
|---|------|----------|-------------|
| 01 | Injectable Full Disk Access Apps | **Critical** | Apps with FDA that can be injected with attacker code |
| 02 | Shortest Attack Path to Full Disk Access | **Critical** | Minimum hops from attacker node to FDA |
| 03 | Electron App TCC Permission Inheritance | **High** | Electron apps passing TCC permissions to child processes |
| 04 | Private Apple Entitlement Audit | **High** | Third-party apps with private Apple entitlements |
| 05 | Apple Event TCC Permission Cascade | **High** | Apps gaining TCC access transitively via Apple Event automation |
| 06 | Multi-hop Injection Chain | **Critical** | Chains of injectable apps leading to high-value TCC permissions |
| 11 | Multi-hop Injection + Apple Event Privilege Escalation | **Critical** | Inject App A, App A automates App B, App B has FDA |
| 12 | TCC Database Write Path (Complete TCC Takeover) | **Critical** | Injectable apps with FDA granting write access to TCC.db |
| 13 | Keychain Credential Access via Injection | **Critical** | Injectable apps with silent Keychain read access |
| 14 | Persistent Root Code Execution via Injectable Apps | **Critical** | Injectable apps whose LaunchDaemons run as root |
| 15 | XPC Service Privilege Escalation | **High** | XPC services with elevated entitlements reachable from injectable apps |
| 24 | Admin Group Privilege Escalation | **High** | Admin-group users owning injectable apps — sudo escalation path |
| 25 | Remote Access Attack Surface | **High** | SSH/Screen Sharing with injectable apps accessible by remote users |
| 27 | Unsandboxed Injectable Apps | **High** | Injectable apps not sandboxed — higher severity injection targets |
| 28 | Firewall-Exposed Injectable Apps | **High** | Injectable apps with firewall allowing inbound connections |
| 29 | Hijackable Launch Daemons | **Critical** | Root LaunchDaemons whose binary is writable by non-root users |
| 30 | XPC Services Without Client Verification | **High** | XPC services lacking SMAuthorizedClients — any process can connect |
| 31 | Transitive FDA via Apple Events / Finder Automation | **Critical** | Apps that can script Finder to gain transitive Full Disk Access |
| 32 | Active Sessions on Injectable Apps | **High** | Users with active sessions who have injectable apps with TCC grants |
| 36 | Sudoers NOPASSWD Rules | **High** | Sudoers rules allowing password-less privilege escalation |
| 38 | Running Injectable Apps with TCC Grants | **Critical** | Currently running injectable apps with valuable TCC permissions |
| 40 | Injectable Apps Sharing Keychain Groups | **High** | Injectable apps sharing Keychain access groups with other apps |
| 41 | Shortest Path from Owned Nodes to Full Disk Access | **Critical** | From any owned node, shortest path to FDA |
| 42 | Reachable High-Value Assets from Owned Nodes | **Critical** | All TCC/keychain/XPC reachable from owned nodes within N hops |
| 43 | User-Centric Access Enumeration | **High** | Given a username, show all reachable TCC, keychain, and apps |
| 44 | All Inbound Paths to Target Asset | **Critical** | All inbound paths from owned nodes to a target bundle_id |
| 45 | Owned Node Blast Radius Ranking | **Critical** | Rank each owned node by count of reachable high-value assets |
| 47 | Shortest Paths from Owned Nodes to Tier 0 Assets | **Critical** | Shortest escalation paths from owned nodes to crown jewels |
| 49 | File Permission Escalation Chains | **Critical** | User can write critical file, modify security policy, gain access |
| 50 | Shell Hook Injection Paths | **High** | Writable shell hooks enabling credential theft and code injection |
| 51 | Unconstrained Injectable Applications | **Critical** | Injectable apps without launch constraints — easiest targets |
| 52 | Cross-Host User Presence (Lateral Movement) | **High** | Users present on multiple hosts — lateral movement paths |
| 53 | Cross-Host Injection Chain (SSH + Injectable FDA) | **Critical** | SSH access to remote host enabling injection of FDA apps |
| 54 | Accessibility API Abuse | **Critical** | Injectable apps with Accessibility permission for GUI control |
| 55 | Injectable Endpoint Security Framework Clients | **Critical** | Injectable ESF apps that could blind security monitoring |
| 56 | Injectable Network Extension Apps | **Critical** | Injectable apps with VPN/content-filter entitlements |
| 58 | Group-Based Capability Escalation | **High** | Users with debugger or remote access via group membership |
| 61 | Ad-Hoc Signed Apps with TCC Grants | **Critical** | Apps signed without real certificate (CS_ADHOC) holding TCC |
| 65 | Bluetooth Attack Surface | **High** | Paired BT devices with injectable apps holding Bluetooth TCC grants |
| 68 | Injectable Apps with iCloud Sync | **High** | Injectable apps with iCloud container entitlements — data exfil risk |
| 69 | CloudKit Container Injection | **High** | Injectable apps with CloudKit entitlements — cloud data access |
| 70 | iCloud Keychain Sync Exposure | **Critical** | Injectable apps with keychain read on hosts with iCloud sync |
| 71 | Password Change Attack Paths | **Critical** | Admin users who can change passwords of users owning privileged apps |
| 86 | Sandbox Escape Vectors via Mach-Lookup | **Critical** | Sandboxed apps with mach-lookup exceptions to privileged XPC |
| 89 | Quarantine Bypass Apps with TCC Grants | **Critical** | Unquarantined apps holding TCC grants — Gatekeeper bypass |
| 95 | High-Risk Applications | **Critical** | Applications with graph-native risk_score >= 7.0 |
| 98 | Memory Safety Risk | **Critical** | Apps affected by memory safety CWEs with injection paths |

### Red Team — Vulnerability & CVE

| # | Name | Severity | Description |
|---|------|----------|-------------|
| 72 | AD-Bound Mac Attack Surface | **Critical** | AD-bound hosts with injectable apps that can access Kerberos tickets |
| 73 | Kerberos Ticket Theft via Injectable Apps | **Critical** | Injectable app reads ccache to impersonate AD user |
| 80 | CVE-Affected Applications | **Informational** | All applications with known CVE associations |
| 81 | CISA KEV + Full Disk Access Applications | **Critical** | FDA apps with CISA Known Exploited Vulnerabilities |
| 82 | High-EPSS Injectable Applications | **Critical** | Injectable apps with high exploitation probability (EPSS > 0.3) |
| 83 | Vulnerability-Enriched Attack Chains | **Critical** | Attack paths where the target app has known CVE associations |
| 84 | Running Injectable Processes with CVEs | **Critical** | Currently running, injectable processes with known CVEs |
| 85 | Version-Matched Vulnerabilities | **Critical** | Applications with version-confirmed CVE matches (precise tier) |
| 92 | APT Group Exposure | **Critical** | APT groups whose techniques map to CVEs affecting this host |

### Blue Team — TCC & Entitlements

| # | Name | Severity | Description |
|---|------|----------|-------------|
| 07 | TCC Grant Overview | **Informational** | Summary of all TCC grants for security audits and baselines |
| 10 | MDM-Managed TCC Permissions | **Informational** | TCC grants silently enforced via MDM profiles |
| 16 | Full TCC Grant Inventory | **Informational** | Complete audit of all TCC grants — service, app, grant method, age |
| 17 | Over-privileged Applications | **High** | Apps with more TCC permissions than typical threshold |
| 18 | Unsigned or Unhardened Apps with TCC Grants | **High** | Apps lacking code signing protections that hold TCC grants |
| 19 | Stale TCC Grants (Orphaned Permissions) | **High** | TCC grants for apps no longer installed on the system |
| 20 | MDM-Managed vs User-Granted TCC Comparison | **Informational** | Compliance comparison of MDM vs user-granted TCC permissions |
| 37 | Unnotarized Apps with TCC Grants | **High** | Apps not notarized by Apple but holding TCC privacy grants |
| 39 | MDM Overgrant to Scripting Interpreters | **Critical** | MDM profiles granting sensitive TCC to scripting interpreters |

### Blue Team — Infrastructure & Hardening

| # | Name | Severity | Description |
|---|------|----------|-------------|
| 08 | Persistence Audit | **High** | Third-party LaunchDaemons/Agents running as root or injectable |
| 09 | Keychain ACL Audit | **High** | Apps with direct Keychain read access via ACL trusted-app list |
| 26 | SIP-Corrected Injection Audit | **Informational** | Apps excluded from injection analysis by SIP protection |
| 33 | Weak Authorization Rights | **High** | Authorization database rights with weakened security settings |
| 34 | Non-Apple Authorization Plugins | **High** | Third-party SecurityAgent plugins that could intercept auth |
| 35 | Non-Apple System Extensions | **High** | Third-party system extensions (network filters, ESF, drivers) |
| 46 | Tier Classification Summary | **Informational** | Classified Application nodes grouped by tier |
| 48 | Critical File Write Access Audit | **Critical** | Users who can write to TCC databases, sudoers, sshd_config |
| 57 | Tier 0 Inbound Control Audit | **Critical** | All inbound attack paths to Tier 0 crown jewel assets |
| 59 | Keychain Crown Jewels | **High** | High-sensitivity keychain items (SSH keys, certs) and who can access them |
| 62 | Apps Signed by Non-Apple Certificate Authorities | **High** | Apps whose signing chain terminates at a non-Apple root CA |
| 63 | Certificate Authority Hierarchy | **Informational** | Complete CA trust chain visualization across all applications |
| 87 | Sandbox Exception Audit | **High** | Sandboxed apps with unconstrained network or file access exceptions |
| 88 | Unquarantined Non-System Applications | **High** | Non-system apps missing quarantine xattr — Gatekeeper bypass |
| 93 | Temporal Priority Vulnerabilities | **High** | CVEs ranked by temporal urgency combining CVSS, EPSS, and age decay |
| 97 | CWE Weakness Class Heatmap | **High** | CWE weakness classes ranked by number of affected applications |
| 99 | ESF Monitoring Gaps | **High** | Critical ESF event types with no active SystemExtension monitoring |
| 100 | Top Recommendations by Affected App Count | **High** | Recommendations ranked by number of applicable applications |
| 101 | Application Remediation Plan | **Informational** | All recommendations for a specific application by bundle_id |

### Blue Team — Enterprise (AD/Kerberos)

| # | Name | Severity | Description |
|---|------|----------|-------------|
| 74 | AD Group to Local Admin Mapping | **Critical** | AD groups mapped to local admin on every AD-bound Mac |
| 75 | Machine Keytab Exposure | **High** | World-readable or injectable keytabs — machine account impersonation |
| 76 | AD Users with Injectable FDA Apps | **Critical** | AD user sessions with injectable FDA apps — FDA + Kerberos tickets |
| 77 | AD Users in Non-Admin Capability Groups | **High** | AD users in capability-granting groups (_developer, wheel) |
| 78 | Weak Kerberos Encryption Defaults | **High** | krb5.conf permitting weak encryption (DES, RC4) |
| 79 | Stale Keytab Detection | **Informational** | Keytabs not rotated in over 1 year |
| 90 | AD to macOS Identity Map | **High** | AD users mapped to macOS local users via SAME_IDENTITY |
| 91 | AD Group Transitive macOS Access | **Critical** | AD group membership reaching macOS TCC grants — cross-domain paths |
| 94 | APT Technique Coverage | **Informational** | Which APT techniques are mitigated by existing controls vs exposed |

### Blue Team — Certificates & Physical

| # | Name | Severity | Description |
|---|------|----------|-------------|
| 60 | Expired Signing Certificates with Active TCC Grants | **High** | Apps signed with expired certificates holding active permissions |
| 64 | Weak Physical Security Posture | **High** | Hosts lacking lockdown mode, BT discoverable, no screen lock |
| 66 | Physical + Remote Combined Risk | **Critical** | Weak physical posture AND enabled remote access — maximum exposure |
| 67 | Physical Security Overview | **Informational** | Complete physical posture inventory per host with all BT devices |

### Forensic — Risk & Remediation

| # | Name | Severity | Description |
|---|------|----------|-------------|
| 21 | High-Value Target Ranking (Attack Value Score) | **Informational** | All apps ranked by weighted attack value score |
| 22 | Trust Boundary Map | **Informational** | All trust relationships between apps (team, automation, XPC) |
| 23 | Full Attack Surface Map | **Informational** | Every inferred attack edge — complete attack surface enumeration |
| 96 | Risk Score Distribution | **Informational** | Histogram of risk levels across all Application nodes |

### Ownership & Tier

| # | Name | Severity | Description |
|---|------|----------|-------------|
| 41 | Shortest Path from Owned Nodes to FDA | **Critical** | From any owned node, shortest escalation path to FDA |
| 42 | Reachable High-Value Assets from Owned Nodes | **Critical** | All TCC/keychain/XPC reachable from owned nodes within N hops |
| 44 | All Inbound Paths to Target Asset | **Critical** | All inbound paths from owned nodes to a target bundle_id |
| 45 | Owned Node Blast Radius Ranking | **Critical** | Rank each owned node by count of reachable high-value assets |
| 46 | Tier Classification Summary | **Informational** | Classified Application nodes grouped by tier |
| 47 | Shortest Paths from Owned Nodes to Tier 0 Assets | **Critical** | Shortest escalation paths from owned to crown jewels |
| 57 | Tier 0 Inbound Control Audit | **Critical** | All inbound attack paths to Tier 0 assets |

Queries 24--101 are documented in their `.cypher` file headers. Run `python3 query_runner.py --describe <number>` for details.

---

## Query Details

### 01 — Injectable Full Disk Access Apps

**File:** `01-injectable-fda-apps.cypher` | **Category:** Red Team | **Severity:** Critical

**Attack chain:** Inject dylib → inherit FDA → read/modify TCC.db → escalate

**What it finds:** Applications that have been granted Full Disk Access AND can be
injected with arbitrary code via DYLD injection or missing library validation.

**Interpretation:**
- Any result here is a critical finding.
- The `injection_methods` column shows the exact technique an attacker would use.
- Apps without a `team_id` are platform binaries — usually not injectable in practice.

---

### 02 — Shortest Path to Full Disk Access

**File:** `02-shortest-path-to-fda.cypher` | **Category:** Red Team | **Severity:** Critical

**Attack chain:** `attacker.payload` → [any path] → Full Disk Access `TCC_Permission`

**What it finds:** The minimum number of hops from an attacker's initial foothold
(represented as the synthetic `attacker.payload` node) to Full Disk Access.

**Interpretation:**
- `path_length = 2` means inject directly into an FDA-holding app (1-hop escalation).
- `path_length = 4` means inject App A → A automates App B → B has FDA (multi-hop).
- Shorter paths = more critical findings.

**Note:** No results = no injectable path to FDA exists on the scanned system. This is a positive finding worth documenting.

---

### 03 — Electron TCC Inheritance Map

**File:** `03-electron-tcc-inheritance.cypher` | **Category:** Red Team | **Severity:** High

**Attack:** `ELECTRON_RUN_AS_NODE=1 /path/to/Electron.app/Contents/MacOS/app node-script.js`

**What it finds:** Electron apps with TCC grants whose child processes (spawned via
`ELECTRON_RUN_AS_NODE` or `--inspect` flag) inherit the parent's TCC permissions.

**Interpretation:** An attacker can run Node.js code inside an Electron app without
injecting the binary, inheriting all its TCC grants via `CHILD_INHERITS_TCC`.

---

### 04 — Private Entitlement Audit

**File:** `04-private-entitlement-audit.cypher` | **Category:** Red Team | **Severity:** High

**What it finds:** Non-system applications that possess private Apple entitlements
(`com.apple.private.*`). These grant elevated privileges reserved for Apple internal use.

**Interpretation:** Third-party apps with private entitlements have been explicitly granted
special access (enterprise/developer tools) or bypassed App Store review. Injectable apps
with private entitlements are critical: injection = privilege theft.

---

### 05 — Apple Event TCC Cascade

**File:** `05-appleevent-tcc-cascade.cypher` | **Category:** Red Team | **Severity:** High

**Attack:** App A → `CAN_SEND_APPLE_EVENT` → App B → invoke B's privileged action

**What it finds:** Apps that can send Apple Events to a more-privileged app, gaining
transitive access to that app's TCC permissions without holding them directly.

**Interpretation:** If App A (injectable, no TCC) can automate App B (has FDA), injecting
App A lets an attacker invoke App B via Apple Events to perform FDA-level operations.
Common real-world TCC bypass technique.

---

### 06 — Multi-hop Injection Chain

**File:** `06-injection-chain.cypher` | **Category:** Red Team | **Severity:** Critical

**What it finds:** Chains where the attacker injects one or more apps in sequence,
ultimately reaching an app with a high-value TCC permission. Depth limited to 3 hops;
increase `[*1..N]` for deeper searches.

---

### 07 — TCC Grant Overview (Blue Team)

**File:** `07-tcc-grant-overview.cypher` | **Category:** Blue Team | **Severity:** Informational

**What it finds:** Three views of TCC grant data (3 separate Cypher statements):
1. Permission distribution — which permissions are most commonly granted
2. Most-permissioned apps — apps with the widest TCC access
3. Authorization reason — how each grant was established (user, MDM, entitlement)

**Note:** Contains 3 Cypher statements separated by `;`. Run each block individually
in Neo4j Browser (Ctrl+Enter per block), or use `query_runner.py` (runs first block).

---

### 08 — Persistence Audit

**File:** `08-persistence-audit.cypher` | **Category:** Blue Team | **Severity:** High

**What it finds:** Third-party LaunchDaemons and LaunchAgents that run as root OR are
associated with an injectable application. An attacker who injects into a persistence
item's parent app gains persistent code execution as root.

**Interpretation:** `runs_as_root=true` + `app_is_injectable=true` is the worst case.

---

### 09 — Keychain ACL Audit

**File:** `09-keychain-acl-audit.cypher` | **Category:** Blue Team | **Severity:** High

**What it finds:** Applications explicitly listed in Keychain item ACLs — meaning those
apps can read the stored credential without prompting the user.

**Interpretation:** Injectable apps with `CAN_READ_KEYCHAIN` are silent credential theft
vectors. Prioritize results where `app_is_injectable = true`.

---

### 10 — MDM-Managed TCC Permissions

**File:** `10-mdm-managed-tcc.cypher` | **Category:** Blue Team | **Severity:** Informational

**What it finds:** TCC permissions enforced via MDM configuration profiles.
MDM grants cannot be revoked by the user and take precedence over manual settings.

**Interpretation:** Injectable apps with MDM-granted TCC permissions are particularly
dangerous — injecting them inherits silently-granted access without any user prompt.

---

### 11 — Multi-hop Injection + Apple Event Privilege Escalation

**File:** `11-multi-hop-injection-chain.cypher` | **Category:** Red Team | **Severity:** Critical

**Parameters:** `$target_service` (default: `kTCCServiceSystemPolicyAllFiles`)

**Attack:** Inject App A → App A automates App B (Apple Event) → App B has `$target_service`

**What it finds:** Two-step attack chains combining injection with Apple Event automation.
Broader than query 06 — finds paths where the mid-hop uses automation rather than injection.
Use `--param target_service=kTCCServiceScreenCapture` to hunt different target permissions.

---

### 12 — TCC Database Write Path (Complete TCC Takeover)

**File:** `12-tcc-db-write-path.cypher` | **Category:** Red Team | **Severity:** Critical

**Attack:** Inject FDA app → write TCC.db → grant arbitrary permissions to any app

**What it finds:** Injectable apps with Full Disk Access. FDA means write access to
the user-level TCC.db (and with additional escalation, the system-level one).

**Interpretation:** Any result is a total TCC takeover vector. An attacker who injects
one of these apps can grant themselves any TCC permission on the system.

---

### 13 — Keychain Credential Access via Injection

**File:** `13-keychain-via-injection.cypher` | **Category:** Red Team | **Severity:** Critical

**Attack:** Inject app → inherit `CAN_READ_KEYCHAIN` → extract credentials silently

**What it finds:** Injectable applications that hold silent Keychain read access.
Requires Phase 3.3 (Keychain ACL scanner) data.

**Interpretation:** These apps are credential theft vectors. Injecting the process
gives the attacker all secrets accessible by that app's ACL entry.

---

### 14 — Persistent Root Code Execution via Injectable Apps

**File:** `14-persistence-as-root.cypher` | **Category:** Red Team | **Severity:** Critical

**Attack:** Inject app → LaunchDaemon runs injected code as root on every boot

**What it finds:** Apps registered as LaunchDaemons running as root where the app
itself is injectable. Requires Phase 3.2 (persistence scanner) data.

**Interpretation:** Results here are persistent root backdoor vectors — not just
one-time escalation, but code that re-executes as root on every system startup.

---

### 15 — XPC Service Privilege Escalation

**File:** `15-xpc-privilege-escalation.cypher` | **Category:** Red Team | **Severity:** High

**Attack:** Inject client app → call XPC service → XPC inherits entitlements to caller

**What it finds:** XPC services with elevated entitlements reachable via
`COMMUNICATES_WITH` from injectable applications. Requires Phase 3.1 (XPC) data.

---

### 16 — Full TCC Grant Inventory

**File:** `16-tcc-grant-audit.cypher` | **Category:** Blue Team | **Severity:** Informational

**Parameters:** `$scope` (optional: `user` or `system`, default: all)

**What it finds:** Complete audit of all TCC grants — service name, app, bundle ID,
grant type (user/MDM/entitlement), and approximate grant age.

**Use case:** Baseline establishment before a policy change, compliance reporting,
or identifying grants that predate a known security incident.

---

### 17 — Over-privileged Applications

**File:** `17-overprivileged-apps.cypher` | **Category:** Blue Team | **Severity:** High

**Parameters:** `$min_permissions` (default: `3`) — minimum distinct TCC services to flag

**What it finds:** Apps holding more TCC permissions than the specified threshold.
Results include the full permission list and injectability status.

**Interpretation:** High permission counts + injectable = priority remediation target.
Use `--param min_permissions=5` for a tighter filter in large environments.

---

### 18 — Unsigned or Unhardened Apps with TCC Grants

**File:** `18-unsigned-or-unhardened-with-grants.cypher` | **Category:** Blue Team | **Severity:** High

**What it finds:** Apps that have been granted TCC permissions but lack basic code
signing protections (unsigned, missing hardened runtime, or disabled library validation).

**Interpretation:** These apps represent grants made to principals that can be trivially
hijacked. Any TCC grant to an unsigned or unhardened app should be reviewed and revoked.

---

### 19 — Stale TCC Grants (Orphaned Permissions)

**File:** `19-stale-tcc-grants.cypher` | **Category:** Blue Team | **Severity:** High

**What it finds:** TCC grants referencing bundle IDs for which no installed Application
node exists in the graph. These are grants for uninstalled apps — leftover attack surface.

**Interpretation:** Stale grants can be exploited by an attacker who re-installs
an application using the same bundle ID, inheriting the existing TCC grants instantly.

---

### 20 — MDM-Managed vs User-Granted TCC Comparison

**File:** `20-mdm-vs-user-grants.cypher` | **Category:** Blue Team | **Severity:** Informational

**What it finds:** Side-by-side breakdown of MDM-enforced grants vs user-granted TCC
permissions. Useful for compliance validation: are production grants consistent with
what MDM policy dictates?

---

### 21 — High-Value Target Ranking (Attack Value Score)

**File:** `21-high-value-targets.cypher` | **Category:** Forensic | **Severity:** Informational

**What it finds:** All applications ranked by weighted attack value score:
- `tcc_count × 10` — base TCC surface (each allowed grant = +10)
- `+ injectability × 50` — injectable process flag (+50 if injectable)
- `+ private_ent_count × 20` — private entitlement bonus (+20 per entitlement)
- `+ keychain_count × 30` — Keychain ACL entries (+30 per item)
- `+ daemon_count × 40` — persistence bonus (+40 per LaunchDaemon)

**Use case:** Prioritize hardening effort; focus on highest-scored apps first.

---

### 22 — Trust Boundary Map

**File:** `22-trust-boundary-map.cypher` | **Category:** Forensic | **Severity:** Informational

**Parameters:** `$app_name` (optional) — filter to a single app's trust relationships

**What it finds:** All trust relationships between applications:
- Same team ID (code-signing trust chain)
- Apple Event automation targets (`CAN_SEND_APPLE_EVENT`)
- XPC communication peers (`COMMUNICATES_WITH`)
- Injection vectors (`CAN_INJECT_INTO`)

**Use case:** Blast-radius analysis — given one compromised app, what can an attacker reach?

---

### 23 — Full Attack Surface Map

**File:** `23-full-attack-surface.cypher` | **Category:** Forensic | **Severity:** Informational

**What it finds:** Every inferred attack edge in the graph using `UNION ALL` across
all relationship types (`CAN_INJECT_INTO`, `CHILD_INHERITS_TCC`, `CAN_SEND_APPLE_EVENT`,
`COMMUNICATES_WITH`, `CAN_READ_KEYCHAIN`). Complete enumeration of the attack surface.

**Use case:** Full export for offline analysis, or input to external graph tools.
Pipe to `--format csv` and load into Gephi or similar for visual exploration.

---

## Running Queries

### query_runner.py (recommended)

```bash
# List all queries with category/severity colour coding
python3 query_runner.py --list

# Run a specific query (table output)
python3 query_runner.py --run 01

# Run with parameters
python3 query_runner.py --run 17 --param min_permissions=5
python3 query_runner.py --run 11 --param target_service=kTCCServiceScreenCapture

# Output formats
python3 query_runner.py --run 21 --format json
python3 query_runner.py --run 23 --format csv > attack-surface.csv

# Run all queries
python3 query_runner.py --run all

# Custom Neo4j connection
python3 query_runner.py --neo4j bolt://host:7687 --neo4j-user neo4j --neo4j-password mypass --run 01
```

### Neo4j Browser (recommended for visualization)

1. Open `http://localhost:7474`
2. Log in with `neo4j` / `rootstock`
3. Load the Browser Guide: `:play http://localhost:8001/rootstock-guide.html`
4. Apply the GraSS stylesheet from `browser/rootstock-style.grass`
5. Paste a query into the editor (⌘K to clear, ⌘Enter to run)

### cypher-shell (command line)

```bash
# Run a single query file
cat graph/queries/01-injectable-fda-apps.cypher | \
  cypher-shell -u neo4j -p rootstock --format plain

# Or pipe via docker
cat graph/queries/01-injectable-fda-apps.cypher | \
  docker exec -i rootstock-neo4j cypher-shell -u neo4j -p rootstock
```

---

## Interpreting Zero Results

| Query | Zero results means |
|---|---|
| 01, 12 | No injectable apps have FDA — strong security posture |
| 02 | No attack path from attacker node to FDA exists |
| 03 | No Electron apps with TCC grants found |
| 04 | No third-party apps with private entitlements |
| 05, 11 | No Apple Event + TCC cascade found |
| 06 | No multi-hop injection path to critical permissions |
| 13 | No injectable apps hold Keychain ACL entries |
| 14 | No injectable apps linked to root LaunchDaemons |
| 15 | No injectable apps reach privileged XPC services |
| 19 | No stale grants for uninstalled apps — clean TCC state |

Zero results on queries 01, 02, 06, 12, 13, 14 are **positive findings** worth documenting
in your security report.
