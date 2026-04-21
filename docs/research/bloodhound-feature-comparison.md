# BloodHound → macOS Feature Comparison

> For each BloodHound feature: what is the macOS analog, and does Rootstock implement it?
>
> Last updated: 2026-03-20

---

## 1. Node Types

| BloodHound Node | macOS Analog | Rootstock Status |
|---|---|---|
| **User** | macOS local/network user (`dscl . -list /Users`) | ✅ `User` node — name, shell, home_dir, is_hidden |
| **Group** | macOS local groups (`dscl . -list /Groups`) | ✅ `LocalGroup` node — name, gid, members |
| **Computer** | The Mac itself | ✅ `Computer` node — hostname, macos_version, scan_id, posture flags |
| **Domain** | N/A — macOS has no AD domain concept natively | ❌ N/A (single-host tool) |
| **OU** | N/A — no native OU concept | ❌ N/A |
| **GPO** | MDM Configuration Profiles (Jamf, Mosyle, Kandji) | ✅ `MDM_Profile` node — identifier, display_name, organization |
| **Container** | App Bundles (`.app` directories) | ✅ `Application` node — bundle_id, path, version, 22 properties |
| **CertTemplate** | Code Signing Certificates / Provisioning Profiles | ✅ `CertificateAuthority` nodes — full chain with `SIGNED_BY_CA` + `ISSUED_BY` edges, queries 60-63 |
| **EnterpriseCA** | Apple Root CA / Developer ID CA | ✅ `CertificateAuthority` node — intermediate CAs in chain |
| **RootCA** | Apple Root Certificate Authority | ✅ `CertificateAuthority{is_root: true}` — root CA nodes |
| **ADLocalGroup** | macOS local groups (admin, staff, wheel, _developer) | ✅ `LocalGroup` node |
| **AZApp / AZServicePrincipal** | macOS Applications / Background Services | ✅ `Application` + `XPC_Service` + `LaunchItem` |
| **AZKeyVault** | macOS Keychain | ✅ `Keychain_Item` node — label, kind, service, access_group, sensitivity |
| **AZRole** | TCC Permission (privacy grant acting as a role) | ✅ `TCC_Permission` node — service, display_name |
| **IssuancePolicy** | Entitlement (code-signing privilege) | ✅ `Entitlement` node — name, is_private, category, is_security_critical |

### macOS-Specific Nodes (no BloodHound equivalent)

| Rootstock Node | macOS Concept | Count | BloodHound Equivalent |
|---|---|---|---|
| `TCC_Permission` | Privacy grant (FDA, Camera, Mic, etc.) | — | Closest: AZRole |
| `Entitlement` | Code-signing privilege declaration | — | Closest: CertTemplate permissions |
| `XPC_Service` | Mach-port IPC service (launchd-managed) | — | No equivalent |
| `LaunchItem` | Persistence mechanism (daemon/agent/cron/login item/hook) | — | Closest: scheduled tasks |
| `RemoteAccessService` | SSH / Screen Sharing service status | — | Closest: CanRDP/CanPSRemote edges |
| `FirewallPolicy` | macOS Application Firewall (ALF) per-app rules | — | No equivalent |
| `LoginSession` | Active login session (console, SSH, tmux) | — | Closest: HasSession |
| `AuthorizationRight` | Authorization Services right (system.privilege.admin) | — | No equivalent |
| `AuthorizationPlugin` | SecurityAgent plugin | — | No equivalent |
| `SystemExtension` | Network/endpoint security/driver extension | — | No equivalent |
| `SudoersRule` | Sudoers NOPASSWD entry | — | No equivalent |
| `CriticalFile` | Security-critical file (TCC.db, keychain, sudoers) | — | No equivalent |
| `Computer` | Scanned host with posture data | — | Equivalent: Computer node |

**Total: 18 node types** (vs BloodHound's ~35 across AD + Azure)

---

## 2. Edge / Relationship Types

### Identity & Membership

| BloodHound Edge | macOS Analog | Rootstock Status |
|---|---|---|
| **MemberOf** | User → Group membership | ✅ `MEMBER_OF` (User → LocalGroup) |
| **AdminTo** | User in `admin` group → full local admin | ✅ Derivable via `MEMBER_OF → LocalGroup{name:'admin'}` + query 24 |
| **HasSession** | Active login sessions (Console, SSH, screen sharing) | ✅ `HAS_SESSION` (User → LoginSession) |
| **Contains** | OU/Container hierarchy | N/A |
| **Owns** | File/resource ownership | ✅ `CAN_WRITE` (User → CriticalFile) via file ACL inference |

### Privilege Escalation

| BloodHound Edge | macOS Analog | Rootstock Status |
|---|---|---|
| **GenericAll / GenericWrite / WriteDacl** | File ACL manipulation | ✅ `CAN_WRITE` + `CAN_MODIFY_TCC` (file ACL-based) |
| **ForceChangePassword** | `dscl . -passwd` (requires admin) | ✅ `CAN_CHANGE_PASSWORD` (inferred from admin group + sudo) |
| **DCSync** | N/A — no domain controller concept | ❌ N/A |
| **ReadLAPSPassword / ReadGMSAPassword** | N/A — no LAPS/GMSA on macOS | ❌ N/A |
| **CanRDP** | Screen Sharing permission (ARD/VNC) | ✅ `RemoteAccessService{service:'screen_sharing'}` + `ACCESSIBLE_BY` |
| **CanPSRemote** | SSH access | ✅ `RemoteAccessService{service:'ssh'}` + `ACCESSIBLE_BY` |
| **ExecuteDCOM** | Apple Events / AppleScript automation | ✅ `CAN_SEND_APPLE_EVENT` (inferred) |
| N/A | Accessibility API GUI control | ✅ `CAN_CONTROL_VIA_A11Y` (inferred) |
| N/A | Debugger attachment via _developer group | ✅ `CAN_DEBUG` (inferred) |
| N/A | ESF client blinding | ✅ `CAN_BLIND_MONITORING` (inferred) |

### Code Signing / Trust

| BloodHound Edge | macOS Analog | Rootstock Status |
|---|---|---|
| **TrustedBy / SameForestTrust** | Same Team ID trust | ✅ `SIGNED_BY_SAME_TEAM` |
| **GoldenCert** | Stolen Apple Developer Certificate | ⚠️ Partial — cert chain modeled (queries 60-62), stolen cert detection out of scope |
| N/A | DYLD injection (3 methods + Electron) | ✅ `CAN_INJECT_INTO` (4 injection methods) |
| N/A | Electron child process TCC inheritance | ✅ `CHILD_INHERITS_TCC` |

### Lateral Movement

| BloodHound Edge | macOS Analog | Rootstock Status |
|---|---|---|
| **HasSession** → credential theft | Keychain ACL → credential access | ✅ `CAN_READ_KEYCHAIN` |
| **AdminTo** → local admin | sudo / admin group membership | ✅ `SUDO_NOPASSWD` + `MEMBER_OF` + query 24 |
| N/A | XPC service privilege escalation | ✅ `COMMUNICATES_WITH` |
| N/A | Persistence via LaunchDaemon/Agent | ✅ `PERSISTS_VIA` + `RUNS_AS` |
| N/A | Hijackable persistence | ✅ `CAN_HIJACK` (writable daemon binaries) |
| N/A | MDM-managed TCC policy | ✅ `CONFIGURES` |
| N/A | Transitive FDA via Finder automation | ✅ `HAS_TRANSITIVE_FDA` |
| N/A | Shared Keychain group access | ✅ `SHARES_KEYCHAIN_GROUP` |
| N/A | MDM overgrant detection | ✅ `MDM_OVERGRANT` |
| N/A | Shell hook injection | ✅ `CAN_INJECT_SHELL` |
| N/A | TCC database direct modification | ✅ `CAN_MODIFY_TCC` (via file ACL chain) |
| N/A | File ACL-based write access | ✅ `CAN_WRITE` + `PROTECTS` |

### Multi-Host

| BloodHound Edge | macOS Analog | Rootstock Status |
|---|---|---|
| **CanRDP / CanPSRemote** (cross-host) | SSH / Screen Sharing across hosts | ✅ `ACCESSIBLE_BY` + `LOCAL_TO` + queries 52-53 |
| **Contains** (computer in domain) | App installed on host | ✅ `INSTALLED_ON` (Application → Computer) |
| N/A | User exists on host | ✅ `LOCAL_TO` (User → Computer) |

### Certificate Services (ADCS)

| BloodHound Edge | macOS Analog | Rootstock Status |
|---|---|---|
| **ADCSESC1–ESC13** | N/A — no ADCS on macOS | ❌ N/A |
| **ManageCA / ManageCertificates** | System Keychain cert management | ❌ Not modeled |

### NTLM / Kerberos

For AD-joined Macs, Rootstock detects AD binding status and Kerberos artifacts (ccache, keytab, config) to model the cross-boundary bridge between macOS and AD. Five edge types support this: `MAPPED_TO` (ADGroup → LocalGroup), `FOUND_ON` (KerberosArtifact → Computer), `HAS_KERBEROS_CACHE` (User → KerberosArtifact), `HAS_KEYTAB` (Computer → KerberosArtifact), `CAN_READ_KERBEROS` (injectable app → artifact, inferred).

**Total: 35 edge types** (vs BloodHound's ~84 across AD + Azure)

---

## 3. Attack Path Categories

| BloodHound Attack Category | macOS Analog | Rootstock Status |
|---|---|---|
| **Kerberoasting** | Kerberos ticket theft via injectable apps on AD-bound Macs | ✅ AD binding detection + Kerberos artifact collection + CAN_READ_KERBEROS inference |
| **AS-REP Roasting** | N/A | ❌ Out of scope |
| **DCSync** | N/A | ❌ Out of scope |
| **LAPS Password Reading** | N/A | ❌ Out of scope |
| **ADCS Certificate Abuse** | N/A (no ADCS on macOS) | ❌ Out of scope |
| **NTLM Relay** | N/A (standalone macOS) | ❌ Out of scope |
| **ACL/DACL Abuse** | File permission / xattr abuse | ✅ File ACL collector + `CAN_WRITE` / `CAN_MODIFY_TCC` inference |
| **Lateral Movement (RDP/PSRemote)** | SSH / Screen Sharing / ARD | ✅ `RemoteAccessService` + `ACCESSIBLE_BY` + queries 25, 52-53 |
| **Golden Ticket / SID History / Delegation** | N/A | ❌ Out of scope |
| **GPO Abuse** | MDM Profile Abuse | ✅ `MDM_OVERGRANT` inference + query 39 |
| **Local Admin Abuse** | sudo / admin group → full control | ✅ `MEMBER_OF → LocalGroup{name:'admin'}` + `SUDO_NOPASSWD` + query 24, 36 |
| **Session Credential Theft** | Keychain credential access via injection | ✅ Query 13 (keychain-via-injection) |
| **Owned Node Pathfinding** | Mark compromised, find escalation | ✅ `mark_owned.py` + queries 41-47 |
| **Tier 0 / High Value Targeting** | Crown jewel identification | ✅ `tier_classification.py` + queries 46-47 |
| N/A | **TCC Grant Abuse** (DYLD inject → inherit FDA) | ✅ Queries 01, 02, 06, 12 |
| N/A | **Electron TCC Inheritance** | ✅ Query 03 |
| N/A | **Apple Event Cascade** | ✅ Queries 05, 11 |
| N/A | **Accessibility API Abuse** | ✅ Query 54 (a11y abuse) |
| N/A | **XPC Privilege Escalation** | ✅ Query 15 |
| N/A | **Persistent Root Execution** | ✅ Query 14 |
| N/A | **Stale TCC Grant Reuse** | ✅ Query 19 |
| N/A | **Private Entitlement Abuse** | ✅ Query 04 |
| N/A | **TCC DB Write (Full Takeover)** | ✅ Query 12 |
| N/A | **ESF Client Blinding** | ✅ Query 55 (injectable ESF clients) |
| N/A | **Network Extension Interception** | ✅ Query 56 (injectable VPN/content filters) |
| N/A | **Shell Hook Injection** | ✅ Query 50 |
| N/A | **Debugger Attachment via Group** | ✅ Query 58 (group capabilities) |
| N/A | **Scan Diffing / Posture Trending** | ✅ `diff_scans.py` (compares scans over time) |

---

## 4. Data Collection

| BloodHound Collector (SharpHound) | macOS Equivalent | Rootstock Status |
|---|---|---|
| **LDAP queries** (AD objects) | `dscl` / OpenDirectory queries | ✅ User, group, membership enumeration |
| **SMB named pipes** (sessions) | N/A | ❌ N/A |
| **ACL enumeration** (AD DACLs) | File ACLs / extended attributes | ✅ POSIX + extended ACLs on security-critical paths |
| **Certificate Services** (AD CS) | Code signing certificates | ✅ Full certificate chain — CA nodes, `SIGNED_BY_CA`, `ISSUED_BY`, expiry + trust validation |
| **Group membership** | Local groups via `dscl` | ✅ All local groups with full membership |
| **User properties** | `dscl . -read /Users/<name>` | ✅ Shell, home_dir, is_hidden, group membership |
| **Session enumeration** | Active login sessions | ✅ `who` output → LoginSession nodes |
| N/A | **TCC database** (user + system) | ✅ Full SQLite parsing with scope detection |
| N/A | **Code signing** (hardened runtime, library validation) | ✅ Security.framework + codesign CLI |
| N/A | **Entitlements** (per-app privilege declarations) | ✅ 7-category classification with security criticality |
| N/A | **XPC services** (launchd plist enumeration) | ✅ All LaunchDaemon/Agent directories |
| N/A | **Keychain ACLs** (metadata, trusted apps) | ✅ SecItemCopyMatching (no secrets) + sensitivity classification |
| N/A | **Persistence** (daemons, agents, cron, login items, hooks) | ✅ 5 persistence sources + ownership/writability |
| N/A | **MDM profiles** (configuration + TCC policies) | ✅ `profiles -C` parsing |
| N/A | **Authorization DB** (rights + plugins) | ✅ Weak rights + non-Apple plugins |
| N/A | **System extensions** (network, endpoint security, drivers) | ✅ Type, team_id, enabled status |
| N/A | **Sudoers rules** (NOPASSWD entries) | ✅ Full parsing with user+command+host |
| N/A | **Running processes** (point-in-time snapshot) | ✅ PID, user, bundle_id correlation |
| N/A | **File ACLs** (TCC.db, keychain, sudoers, SSH) | ✅ 8 critical path categories |
| N/A | **Firewall rules** (ALF per-app status) | ✅ Enabled, stealth mode, per-app allow/deny |
| N/A | **Remote access** (SSH + Screen Sharing config) | ✅ Enabled state + access group mapping |
| N/A | **User details** (shell, home directory) | ✅ Per-user enrichment |

**Total: 20+ collector data sources** (vs SharpHound's 12+ AD/Azure sources)

---

## 5. Analysis & Visualization

| BloodHound Feature | macOS Analog | Rootstock Status |
|---|---|---|
| **Interactive graph UI** (Sigma.js) | Neo4j Browser + HTML viewer | ✅ `viewer.py` generates Canvas-based HTML with pre-computed layout, progressive disclosure, and semantic zoom; Neo4j Browser for ad-hoc queries |
| **Shortest path finding** | Cypher `shortestPath()` | ✅ Queries 02, 41, 44, 47 |
| **Pre-built queries** (170+ in library) | Pre-built Cypher library | ✅ **76 queries** (red team, blue team, forensic) |
| **Custom Cypher editor** | Neo4j Browser Cypher console | ✅ Via Neo4j Browser |
| **Tier Zero / High Value marking** | Tier 0/1/2 classification | ✅ `tier_classification.py` + queries 46-47 |
| **"Owned" node marking** | Mark compromised nodes for pathfinding | ✅ `mark_owned.py` + `clear_owned.py` + queries 41-47 |
| **Blast radius analysis** | Reachability from owned nodes | ✅ Queries 42, 45 |
| **Inbound control audit** | Who can reach Tier 0 assets? | ✅ Query 57 (Tier 0 inbound control) |
| **Posture tracking** (Enterprise) | Scan comparison over time | ✅ `diff_scans.py` (posture trending) |
| **Multi-host correlation** | Cross-host attack paths | ✅ `merge_scans.py` + queries 52-53 |
| **OpenGraph export** (CE v8+) | BloodHound CE integration | ✅ `opengraph_export.py` (22 nodes, 38 edges) |
| **REST API** | N/A | ✅ `server.py` — FastAPI with query execution, owned marking, tier classification |
| **RBAC / Multi-user** | N/A | ❌ Single-user tool — out of scope |
| **Markdown report generation** | N/A in BH | ✅ `report.py` with Mermaid diagrams |
| **HTML report generation** | N/A in BH | ✅ `report.py --format html` |
| **Graphviz DOT export** | N/A in BH | ✅ `report_graphviz.py` |
| **CSV / JSON export** | N/A in BH | ✅ `query_runner.py --format csv|json` |
| **One-command pipeline** | N/A in BH | ✅ `pipeline.sh` (schema → import → infer → classify → report) |

---

## 6. Inference Engine Comparison

BloodHound CE performs minimal post-collection inference (mostly during SharpHound collection itself). Rootstock runs a dedicated inference engine with **13 modules**:

| Module | Edge Created | Attack Vector |
|---|---|---|
| `infer_injection.py` | `CAN_INJECT_INTO` | DYLD_INSERT, missing library validation, Electron |
| `infer_electron.py` | `CHILD_INHERITS_TCC` | Electron child process TCC inheritance |
| `infer_automation.py` | `CAN_SEND_APPLE_EVENT` | Apple Events cross-process automation |
| `infer_finder_fda.py` | `HAS_TRANSITIVE_FDA` | Transitive FDA via Finder automation |
| `infer_mdm_overgrant.py` | `MDM_OVERGRANT` | MDM granting FDA to scripting interpreters |
| `infer_keychain_groups.py` | `SHARES_KEYCHAIN_GROUP` | Shared keychain access group exposure |
| `infer_file_acl.py` | `CAN_WRITE`, `PROTECTS`, `CAN_MODIFY_TCC` | File ACL-based privilege escalation |
| `infer_shell_hooks.py` | `CAN_INJECT_SHELL` | Writable shell config injection |
| `infer_accessibility.py` | `CAN_CONTROL_VIA_A11Y` | Accessibility API GUI control abuse |
| `infer_esf.py` | `CAN_BLIND_MONITORING` | ESF client blinding via injection |
| `infer_group_capabilities.py` | `CAN_DEBUG` | _developer group debugger attachment |
| `infer_password.py` | `CAN_CHANGE_PASSWORD` | Admin/sudo password change (ForceChangePassword analog) |
| `infer_kerberos.py` | `CAN_READ_KERBEROS` | Injectable app → Kerberos artifact access (FDA, same-user, world-readable) |

All modules are idempotent (MERGE-based), carry `{inferred: true}` on edges, and run in dependency order.

---

## 7. Summary Scorecard

| Category | BloodHound | Rootstock | Notes |
|---|---|---|---|
| **AD Node Types** | 15 | 0 | Out of scope |
| **Azure Node Types** | 20 | 0 | Out of scope |
| **macOS-Native Node Types** | 0 | **18** | Rootstock-only |
| **AD Edge Types** | 84 | 0 | Out of scope |
| **macOS Edge Types** | 0 | **30** | Rootstock-only |
| **Attack Path Categories (AD)** | ~15 | 0 | Out of scope |
| **Attack Path Categories (macOS)** | 0 | **28+** | Rootstock-only |
| **Pre-built Queries** | 170+ | **71** | Different domains |
| **Collector Data Sources** | 12+ (AD/Azure) | **20+** (macOS-native) | Different domains |
| **Inference Modules** | Minimal | **12** | Rootstock advantage |
| **Interactive UI** | Full web UI | `viewer.py` Canvas HTML + Neo4j Browser | ✅ Implemented |
| **REST API** | Full RBAC API | `server.py` (FastAPI) | ✅ Implemented |
| **Report Generation** | None built-in | **Markdown + HTML + Graphviz** | ✅ Rootstock advantage |
| **Posture Trending** | BH Enterprise only | `diff_scans.py` | ✅ Implemented |
| **Multi-host** | Multi-domain + Azure | `merge_scans.py` | ✅ Implemented |
| **OpenGraph Export** | Native | `opengraph_export.py` | ✅ Integrated |
| **One-command Pipeline** | SharpHound → BH | `pipeline.sh` | ✅ Implemented |

---

## 8. Key Insight

BloodHound and Rootstock are **complementary, not competing**. BloodHound models identity-centric trust (AD users → groups → permissions → domain controllers). Rootstock models app-centric trust (macOS apps → TCC → entitlements → injection → Keychain → persistence). The overlap is near-zero — every attack path Rootstock discovers is invisible to BloodHound, and vice versa.

Integration is possible via `opengraph_export.py` which produces BloodHound CE v8+ OpenGraph JSON for all 22 Rootstock node types and 38 edge types. Cross-domain edges map Rootstock `User` nodes to BloodHound `AZUser`/`User` nodes for environments where macOS hosts are joined to AD. With AD binding detection and Kerberos artifact collection, Rootstock now models the cross-boundary bridge between macOS and AD directly.

### What Rootstock Does That BloodHound Cannot

1. **TCC grant abuse chains** — DYLD inject into FDA app → inherit Full Disk Access
2. **Electron TCC inheritance** — child process inherits parent's privacy grants
3. **Apple Events cascade** — automation chains through multiple apps
4. **Accessibility API abuse** — GUI control superset of Apple Events
5. **ESF client blinding** — injectable security monitoring bypass
6. **Keychain ACL exploitation** — trusted app injection → credential access
7. **MDM overgrant detection** — scripting interpreters with FDA via MDM
8. **File ACL → TCC modification** — writable TCC.db → arbitrary grant creation
9. **Shell hook persistence** — writable .zshrc/.bashrc → session injection
10. **Launch constraint analysis** — categorized binary execution policies

### What BloodHound Does That Rootstock Cannot

1. **Kerberos attack paths** (Kerberoasting, AS-REP, delegation)
2. **ADCS certificate abuse** (ESC1–ESC13)
3. **NTLM relay chains**
4. **Domain trust exploitation**
5. **Azure/Entra ID attack paths**
6. **GPO/OU-based privilege escalation**
