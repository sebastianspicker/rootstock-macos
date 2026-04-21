# Rootstock vs. BloodHound: Comparison

## Overview

Rootstock and BloodHound are both graph-based security analysis tools that map
privilege relationships as directed property graphs. They target fundamentally
different ecosystems but share a common philosophy: **visualize attack paths
that are invisible when examining individual components in isolation.**

| | Rootstock | BloodHound |
|---|---|---|
| **Target** | macOS security boundaries | Active Directory / Azure AD |
| **Data Sources** | TCC, entitlements, code signing, XPC, Keychain, persistence | AD objects, ACLs, sessions, GPOs |
| **Graph DB** | Neo4j | Neo4j (CE), custom (BHE) |
| **Query Language** | Cypher | Cypher |
| **Collector** | Swift CLI (local only) | SharpHound (C#), AzureHound (Go) |
| **Visualization** | Neo4j Browser / custom | BloodHound GUI (Electron) |
| **License** | GPLv3 | GPLv3 (CE), Commercial (BHE) |

## Philosophical Similarities

### 1. Graph-Based Reasoning

Both tools model security relationships as directed graphs where:
- **Nodes** represent entities (apps/services in Rootstock, users/computers in
  BloodHound).
- **Edges** represent security relationships (TCC grants, injection
  vulnerabilities in Rootstock; ACL permissions, session data in BloodHound).
- **Attack paths** are sequences of edges from a compromised starting node to
  a high-value target.

### 2. Separation of Collection and Analysis

Both tools separate the collection phase (running on the target) from the
analysis phase (running on the analyst's workstation):

| Phase | Rootstock | BloodHound |
|-------|-----------|------------|
| Collection | `rootstock-collector` runs on macOS endpoint | SharpHound runs on domain-joined Windows |
| Transport | JSON file (manual transfer) | JSON/ZIP files (manual transfer) |
| Import | Python script -> Neo4j | BloodHound GUI / API -> Neo4j |
| Analysis | Cypher queries + Neo4j Browser | BloodHound GUI + pre-built queries |

### 3. Inferred Relationships

Both tools compute relationships that are not explicitly stated in the raw data:

| Rootstock | BloodHound |
|-----------|------------|
| `CAN_INJECT_INTO` (from code signing flags + entitlements) | `CanRDP`, `CanPSRemote` (from session data + ACLs) |
| `CHILD_INHERITS_TCC` (from Electron detection + TCC grants) | `HasSession` (from logged-on users) |
| `CAN_SEND_APPLE_EVENT` (from automation entitlements) | `MemberOf` (from group nesting resolution) |

### 4. Pre-Built Attack Queries

Both tools ship with curated queries for common attack paths:

**Rootstock examples:**
- "Which Electron apps have Full Disk Access?" (TCC escalation via
  `ELECTRON_RUN_AS_NODE`)
- "Which apps lack hardened runtime and have camera access?" (injection +
  privilege theft)
- "Which non-Apple apps have `com.apple.private.tcc.allow`?" (suspicious
  entitlement usage)

**BloodHound examples:**
- "Shortest path to Domain Admins"
- "Find all Kerberoastable users with admin privileges"
- "Identify computers where Domain Admins are logged in"

## Key Differences

### 1. Security Model Complexity

**Active Directory** has a well-documented, hierarchical security model with
ACLs, group policies, and delegation. BloodHound maps this existing model.

**macOS** has a fragmented security model where TCC, entitlements, code signing,
Keychain ACLs, and XPC services are independent subsystems with complex
interactions. Rootstock must synthesize a unified graph from these disparate
sources.

### 2. Collection Scope

**BloodHound** collects from a centralized directory service (Active Directory
or Azure AD). A single SharpHound run can enumerate the entire domain.

**Rootstock** collects from a single macOS endpoint. Multi-host analysis
requires running the collector on each machine and importing all scans into
the same Neo4j database. Cross-host attack paths (e.g., SSH key reuse) are
a planned future feature.

### 3. Network vs. Local

**BloodHound (SharpHound)** makes LDAP queries over the network to domain
controllers. It requires domain credentials and network access.

**Rootstock** is strictly local. It reads files and APIs on the machine where
it runs. No network calls, no remote authentication, no domain membership.

### 4. Stealth Considerations

**SharpHound** generates LDAP traffic that can be detected by monitoring tools
(e.g., Microsoft ATA, Defender for Identity). Defenders actively look for
BloodHound-style enumeration.

**Rootstock** reads local files and calls local APIs. It generates no network
traffic and minimal filesystem access patterns. Detection would require
endpoint monitoring of `SecCodeCopySigningInformation` calls or TCC.db reads,
which are common operations for legitimate tools.

### 5. Platform Maturity

**BloodHound** is a mature project (first released 2016) with:
- Extensive community-contributed queries
- Commercial enterprise edition (BloodHound Enterprise)
- Integration with offensive tools (Cobalt Strike, Covenant, etc.)
- Defensive use cases (identifying and remediating risky paths)

**Rootstock** is an academic research project (2026) focused on:
- Demonstrating that macOS security boundaries can be modeled as a graph
- Providing a foundation for macOS-specific attack path research
- Enabling security auditors to discover non-obvious privilege escalation paths

## Complementary Usage

Rootstock and BloodHound are not competitors -- they are complementary tools
for organizations that manage both macOS and Windows/AD environments.

### Combined Analysis Scenario

1. Run **SharpHound** on the AD domain to map Windows privilege relationships.
2. Run **Rootstock** on each macOS endpoint to map local security boundaries.
3. Import both datasets into the same Neo4j instance.
4. Query cross-platform attack paths:
   - "Can a compromised macOS app with `kTCCServiceSystemPolicyAllFiles` read
     AD credentials stored in the macOS Keychain?"
   - "Which macOS apps have automation access to apps that store domain tokens?"
   - "Are there injectable macOS apps with Kerberos tickets in the Keychain?"

### Future Integration Points

| Feature | Status |
|---------|--------|
| Shared Neo4j database with BloodHound data | Planned (Phase 6) |
| Cross-platform edge inference | Research phase |
| Unified query library | Not started |
| Shared visualization | Not started |

## Technical Comparison

### Node Types

| Rootstock | BloodHound Equivalent | Notes |
|-----------|----------------------|-------|
| `Application` | `Computer` (loosely) | Apps are the primary actors in macOS |
| `TCC_Permission` | (no equivalent) | macOS-specific privacy framework |
| `Entitlement` | (no equivalent) | macOS code signing feature |
| `XPC_Service` | (no equivalent) | macOS IPC mechanism |
| `LaunchItem` | (no equivalent) | macOS persistence mechanism |
| `Keychain_Item` | (no equivalent) | macOS credential storage |
| `MDM_Profile` | `GPO` (loosely) | Configuration management |
| (planned) `User` | `User` | Local macOS users |

### Edge Types

| Rootstock | BloodHound Equivalent | Notes |
|-----------|----------------------|-------|
| `HAS_TCC_GRANT` | `GenericAll`, `WriteDACL` (loosely) | Permission grants |
| `HAS_ENTITLEMENT` | (no equivalent) | Static code signing property |
| `CAN_INJECT_INTO` | `CanPSRemote`, `ExecuteDCOM` (loosely) | Code execution vectors |
| `CHILD_INHERITS_TCC` | `HasSession` (loosely) | Privilege inheritance |
| `CAN_SEND_APPLE_EVENT` | `GenericAll` (loosely) | IPC-based control |
| `PERSISTS_VIA` | (no equivalent) | Persistence mechanisms |
| `CAN_READ_KEYCHAIN` | `DCSync` (very loosely) | Credential access |

### Query Complexity

Both tools express attack paths as variable-length Cypher path queries:

**Rootstock:**
```cypher
// Find apps that can escalate to Full Disk Access via injection
MATCH path = (attacker:Application)-[:CAN_INJECT_INTO]->(target:Application)
      -[:HAS_TCC_GRANT]->(fda:TCC_Permission {service: 'kTCCServiceSystemPolicyAllFiles'})
WHERE fda.auth_value = 2
RETURN path
```

**BloodHound:**
```cypher
// Find shortest path to Domain Admin
MATCH path = shortestPath((user:User)-[*1..]->(group:Group {name: 'DOMAIN ADMINS@DOMAIN.LOCAL'}))
WHERE user.name = 'COMPROMISED_USER@DOMAIN.LOCAL'
RETURN path
```

## Summary

| Dimension | Rootstock | BloodHound |
|-----------|-----------|------------|
| Ecosystem | macOS | Windows AD / Azure AD |
| Maturity | Research project | Production tool (10+ years) |
| Collection | Local-only, no network | Network (LDAP/LDAPS) |
| Scope per run | Single endpoint | Entire domain |
| Primary actors | Applications | Users + Computers |
| Primary edges | TCC grants + injection | ACL permissions + sessions |
| Key insight | macOS security boundaries form exploitable graphs | AD permissions form exploitable graphs |

Rootstock applies BloodHound's graph-based attack path analysis approach
to macOS, filling the gap in security tooling for Apple platforms.
