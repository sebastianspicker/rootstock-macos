# Threat Model

> Documents the assumptions, capabilities, limitations, and ethical boundaries of Rootstock.

## What Rootstock Is

Rootstock is a **passive, read-only analysis tool** that maps macOS security boundaries as a directed property graph. It discovers potential privilege escalation paths by correlating metadata from TCC grants, code signing, entitlements, XPC services, Keychain ACLs, and persistence mechanisms.

It is the macOS equivalent of what [BloodHound](https://github.com/BloodHoundAD/BloodHound) does for Active Directory — graph-based attack path discovery.

## Assumptions

1. **Local access.** The collector runs on the macOS endpoint being analyzed. There is no remote collection capability.
2. **User or root.** The collector runs as the current user by default. Running as root (or with Full Disk Access) unlocks system-level TCC data.
3. **Point-in-time snapshot.** Each scan captures the state at one moment. TCC grants, installed apps, and entitlements can change at any time after the scan.
4. **Cooperative target.** The endpoint is not actively resisting analysis (no anti-forensics). Rootstock does not bypass SIP, Gatekeeper, or other macOS protections.
5. **Trusted graph database.** The Neo4j instance used for analysis is assumed to be under the analyst's control and not exposed to untrusted users.

## What Rootstock Does NOT Do

| Capability | Rootstock | Notes |
|---|---|---|
| Remote collection | No | Requires local execution on the target Mac |
| Secret extraction | No | Reads metadata only — never passwords, keys, or token values |
| Active exploitation | No | Analysis only; does not execute attacks or modify system state |
| Real-time monitoring | No | Point-in-time snapshot; no persistent agent or daemon |
| SIP bypass | No | Respects System Integrity Protection; system TCC.db requires FDA |
| Network calls | No | The collector is strictly local; no telemetry, no uploads |
| Anti-forensics evasion | No | Does not attempt to hide its execution or artifacts |

## Limitations

### Technical Limitations

- **TCC access on macOS 15+.** Starting with macOS 15 Sequoia, reading the user-level TCC.db requires Full Disk Access at the kernel level. Without FDA, the TCC module returns zero grants and logs a recoverable error.
- **SIP-protected apps.** System applications (e.g., Safari, Terminal) are protected by SIP at the kernel level, which prevents DYLD injection regardless of code signing flags. The current injection assessment does not account for SIP, so these apps may appear as injectable when they are not in practice (see TD-006).
- **Schema stability.** Apple changes TCC schemas, entitlement semantics, and security mechanisms with each macOS release. Rootstock uses PRAGMA-based runtime schema detection to be forward-compatible, but new security mechanisms may not be modeled until explicitly added.
- **Inference is necessary conditions, not sufficient.** The `CAN_INJECT_INTO` relationship indicates that the target app _lacks the code signing protections_ that would prevent injection. It does not guarantee that a working exploit exists — additional factors (ASLR, code signature validation timing, sandboxing) may prevent exploitation.
- **Electron inheritance model.** The `CHILD_INHERITS_TCC` relationship for Electron apps assumes the `ELECTRON_RUN_AS_NODE` attack vector. Apple has mitigated this in recent macOS versions for hardened Electron apps, but the mitigation coverage is not comprehensive.
- **Keychain ACL resolution.** Keychain items report their ACL metadata, but the actual access control enforcement depends on keychain lock state, user authentication, and app signature verification — factors not modeled in the graph.

### Scope Limitations

- **macOS only.** Rootstock does not model iOS, iPadOS, or cross-platform trust boundaries.
- **Single-host.** Each scan covers one endpoint. Multi-host correlation (e.g., shared team IDs across a fleet) requires importing multiple scans into the same Neo4j instance — supported but not automated.
- **No user behavior.** The graph models static configuration, not runtime behavior. It cannot detect whether an attack path has been or is being exploited.
- **No network trust.** Network-level trust relationships (firewall rules, VPN configurations, mDNS services) are not modeled.

## Comparison with BloodHound

| Aspect | BloodHound | Rootstock |
|---|---|---|
| **Domain** | Active Directory / Azure AD | macOS-native security boundaries |
| **Graph model** | Identity-centric (users, groups, GPOs, ACLs) | App-centric (TCC, entitlements, code signing) |
| **Node types** | User, Group, Computer, Domain, GPO, OU | Application, TCC_Permission, Entitlement, XPC_Service, Keychain_Item, LaunchItem, MDM_Profile, User |
| **Attack paths** | Kerberoast, DCSync, AdminTo, GenericAll | DYLD injection, TCC abuse, Electron inheritance, Apple Events |
| **Data collection** | SharpHound (C#/.NET), remote LDAP queries | rootstock-collector (Swift), local macOS APIs |
| **Analysis** | Neo4j + custom UI | Neo4j + Cypher query library |
| **Operating system** | Windows / Linux / macOS (collector runs anywhere with AD access) | macOS only (collector must run on target) |
| **Complementary?** | Yes — BloodHound does not model macOS-native boundaries | Yes — Rootstock does not model AD trust relationships |

### Future Integration

BloodHound's [OpenGraph](https://support.bloodhoundenterprise.io/) data model could potentially ingest Rootstock nodes and edges, enabling unified analysis of AD + macOS attack paths in enterprise environments where Macs are joined to Active Directory.

## Ethical Framework

### Intended Use

Rootstock is designed for:
- **Security auditing** of macOS endpoints by authorized administrators
- **Penetration testing** of macOS environments with explicit authorization
- **Academic research** on macOS security boundaries and attack surface analysis
- **Compliance assessment** of TCC grant hygiene and entitlement exposure

### Responsible Use Guidelines

1. **Authorization required.** Only scan systems you own or have explicit written permission to test.
2. **Data handling.** Scan output contains security-sensitive metadata (which apps have FDA, which lack hardened runtime). Treat scan JSON as confidential.
3. **No weaponization.** Rootstock identifies potential attack paths but does not provide exploits. Using the output to develop targeted attacks against unauthorized systems is outside the tool's intended purpose.
4. **Responsible disclosure.** If Rootstock reveals a vulnerability in a third-party application, follow responsible disclosure practices — contact the vendor before publishing.

### What an Attacker Could Learn

An attacker with access to Rootstock scan output could learn:
- Which applications have Full Disk Access, camera, microphone, or other TCC grants
- Which applications are injectable (missing hardened runtime / library validation)
- Which Electron apps could be abused via `ELECTRON_RUN_AS_NODE`
- Which keychain items are accessible to which applications
- Which XPC services run as root and which applications communicate with them
- The complete entitlement surface of every installed application

This is security-relevant metadata that an attacker could otherwise obtain through manual enumeration, but Rootstock makes it immediately visible and queryable. This is exactly why the tool is valuable for defenders — it reveals the same attack surface an adversary would discover, enabling proactive remediation.
