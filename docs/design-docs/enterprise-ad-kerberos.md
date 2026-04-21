# Enterprise Integration: Active Directory & Kerberos

## Motivation

macOS endpoints in enterprise environments are frequently bound to Active Directory
domains. This binding creates a cross-platform trust boundary that traditional
macOS security tools ignore entirely. An AD domain admin who is mapped to a
macOS local admin transitively inherits every TCC grant, Keychain ACL, and
persistence mechanism associated with that local account. Without modelling
these cross-domain identity relationships, Rootstock would miss the most
impactful privilege escalation paths in enterprise environments.

Kerberos credential artifacts (ccache files, keytab files, krb5.conf) are
equally critical. A world-readable ccache in `/tmp` allows any local process
to impersonate the cached principal. A keytab file with weak permissions
enables offline ticket forging. These artifacts are the bridge between
network-level authentication and host-level access.

The integration also extends to BloodHound, the de facto standard for AD
attack path analysis. By importing SharpHound data and exporting Rootstock
data in OpenGraph format, analysts can trace attack paths that span both
Windows AD and macOS security boundaries in a single unified graph.

## Design Overview

The enterprise AD/Kerberos subsystem spans three layers:

```
┌───────────────────────────────────────────────────────────────┐
│                     Swift Collector                           │
│  ActiveDirectoryDataSource     KerberosArtifactDataSource     │
│  ─ dsconfigad -show            ─ /tmp/krb5cc_* scan           │
│  ─ dscl /Search vs dscl .      ─ /etc/krb5.keytab probe      │
│  ─ AD group membership diff    ─ /etc/krb5.conf parse         │
└───────────────────┬───────────────────────┬───────────────────┘
                    │ scan.json             │
┌───────────────────▼───────────────────────▼───────────────────┐
│                    Python Graph Pipeline                       │
│  import_nodes_security_enterprise.py                          │
│  ─ import_ad_binding()           ─ import_kerberos_artifacts()│
│  ─ Enrich Computer node         ─ MERGE KerberosArtifact     │
│  ─ MERGE ADGroup nodes          ─ FOUND_ON, HAS_KERBEROS_CACHE│
│  ─ MAPPED_TO edges              ─ HAS_KEYTAB edges           │
│                                                               │
│  bloodhound_import.py                                         │
│  ─ Parse SharpHound ZIP         ─ MERGE ADUser nodes          │
│  ─ SAME_IDENTITY edges          ─ AD_MEMBER_OF edges          │
│                                                               │
│  infer_kerberos.py                                            │
│  ─ CAN_READ_KERBEROS edges (world-readable artifact detection)│
│                                                               │
│  opengraph_export.py                                          │
│  ─ Export all node types to BloodHound CE OpenGraph JSON       │
└───────────────────────────────────────────────────────────────┘
```

## Implementation Details

### Collector: ActiveDirectoryDataSource

**Location:** `collector/Sources/ActiveDirectory/ActiveDirectoryDataSource.swift`

The collector detects AD binding via `dsconfigad -show`, parsing the output
for key properties: realm, forest, computer account, organizational unit,
and preferred domain controller. No elevation is required.

AD user discovery uses a set-difference approach: `dscl /Search -list /Users`
returns all known users (local + directory), while `dscl . -list /Users`
returns only local users. The difference identifies AD-sourced accounts.
Each is emitted as a `UserDetail` node with `isADUser: true`.

AD group membership detection follows the same pattern. For each
security-relevant group (wheel, staff, com.apple.access_ssh, etc.),
the collector diffs `/Search` and `.` group membership to find members
injected by the directory service. These are emitted as `LocalGroup`
nodes with only the AD-sourced members, which the graph importer MERGEs
with existing group data from `GroupDataSource`.

Admin group mapping parses the `Allowed admin groups` field from
`dsconfigad -show`, creating `ADGroupMapping` entries that map each
AD group name to the local `admin` group.

### Collector: KerberosArtifactDataSource

**Location:** `collector/Sources/KerberosArtifacts/KerberosArtifactDataSource.swift`

Scans three categories of Kerberos artifacts:

1. **ccache files** (`/tmp/krb5cc_*`, `/var/db/krb5cc/`): Credential caches
   containing TGTs and service tickets. The principal hint is inferred from
   the filename pattern `krb5cc_<uid>` by resolving the UID via `getpwuid`,
   never by reading the credential cache contents.

2. **keytab files** (`/etc/krb5.keytab`): Long-term key storage. Only
   metadata (owner, group, mode, modification time) is collected.

3. **krb5.conf** (`/etc/krb5.conf`, `/Library/Preferences/edu.mit.Kerberos`):
   Configuration files parsed for security-relevant settings: default_realm,
   permitted_enctypes, realm names, and the forwardable flag.

For each artifact, the collector records:
- File path, owner, group, POSIX mode
- Whether the file is readable, world-readable, or group-readable
- Modification timestamp (ISO 8601)
- For ccache: principal hint (username inferred from UID)
- For config: parsed krb5.conf fields

The world-readable and group-readable checks use bitwise operations on the
POSIX permission mode (`0o004` for world-read, `0o040` for group-read).

### Graph Import: import_nodes_security_enterprise.py

**`import_ad_binding()`** performs three operations:

1. Enriches the existing `Computer` node with AD properties (realm, forest,
   computer_account, OU, preferred DC) via `SET` on the matched node.

2. Creates `AD_USER_OF` edges linking `User{is_ad_user: true}` nodes to the
   `Computer{ad_bound: true}` node.

3. MERGEs `ADGroup` nodes and creates `MAPPED_TO` edges from `ADGroup` to
   `LocalGroup`. This edge is the key link: it records that membership in
   the AD group grants membership in the local group, which transitively
   grants all the local group's macOS privileges.

**`import_kerberos_artifacts()`** creates:

- `KerberosArtifact` nodes keyed by `path`, with all metadata properties
- `FOUND_ON` edges from `KerberosArtifact` to `Computer`
- `HAS_KERBEROS_CACHE` edges from `User` to `KerberosArtifact` for ccache
  artifacts that have a resolved principal_hint
- `HAS_KEYTAB` edges from `Computer` to `KerberosArtifact` for keytab
  artifacts

### BloodHound Integration: bloodhound_import.py

Parses SharpHound ZIP archives (the standard BloodHound data collection
format). The ZIP contains `users.json` and `groups.json` with SharpHound's
property schema.

**ADUser import:** Each SharpHound user creates an `ADUser` node with
properties: `object_id` (SID), `name` (full principal like
`JOHN.DOE@CONTOSO.COM`), `domain`, `enabled`, `admin_count`, and
`username` (extracted by splitting on `@`).

**SAME_IDENTITY edges:** Case-insensitive match between `ADUser.username`
and `User.name`. This is the critical cross-domain link. A query like
`(ad:ADUser)-[:SAME_IDENTITY]->(u:User)-[:MEMBER_OF]->(g:LocalGroup)`
reveals which AD principals have macOS local group membership.

**AD_MEMBER_OF edges:** From `ADUser` to `ADGroup`, derived from the
SharpHound groups.json `Members` array. Only User-type members are linked.

**Security controls:** The ZIP parser enforces a 100 MB decompressed size
limit per JSON file to prevent zip bomb attacks.

### OpenGraph Export: opengraph_export.py

Exports the full Rootstock graph (all 29 node types, all edge types) in
BloodHound CE v8+ OpenGraph JSON format. Each node type maps to a
`rs_`-prefixed kind (e.g., `Application` becomes `rs_Application`), with
assigned colors and Font Awesome icons for visualization.

The export supports a `--cross-domain` flag for generating cross-domain
analysis views that focus on AD-to-macOS identity mappings.

## Graph Model Impact

### Node Types Added

| Label | Key Property | Source |
|-------|-------------|--------|
| `ADGroup` | `name` | Collector AD binding + BloodHound |
| `ADUser` | `object_id` (SID) | BloodHound SharpHound import |
| `KerberosArtifact` | `path` | Collector filesystem scan |

### Relationships Added

| Relationship | From | To | Meaning |
|-------------|------|-----|---------|
| `MAPPED_TO` | ADGroup | LocalGroup | AD group grants local group membership |
| `AD_USER_OF` | User{is_ad_user} | Computer{ad_bound} | AD user discovered on host |
| `SAME_IDENTITY` | ADUser | User | Cross-domain identity link |
| `AD_MEMBER_OF` | ADUser | ADGroup | AD group membership |
| `FOUND_ON` | KerberosArtifact | Computer | Artifact location |
| `HAS_KERBEROS_CACHE` | User | KerberosArtifact | User's credential cache |
| `HAS_KEYTAB` | Computer | KerberosArtifact | Host keytab |
| `CAN_READ_KERBEROS` | Application | KerberosArtifact | Injectable app can steal credentials |

### Properties Added to Computer Node

`ad_bound`, `ad_realm`, `ad_forest`, `ad_computer_account`, `ad_ou`,
`ad_preferred_dc`

### Inference: infer_kerberos.py

The Kerberos inference module creates `CAN_READ_KERBEROS` edges from
Application nodes to KerberosArtifact nodes when:

1. The KerberosArtifact is world-readable (`is_world_readable = true`)
2. The Application has injection methods (`size(injection_methods) > 0`)

This models the attack path: an attacker who can inject code into a
running application inherits that application's file access privileges.
If a Kerberos ccache or keytab is world-readable, the injected code can
read the credential material and impersonate the cached principal or
use the keytab for authentication.

### Cypher Queries

- **90**: AD to macOS Identity Map -- maps AD principals to local users,
  showing both AD group memberships (from SharpHound) and local group
  memberships (from collector). The query joins through SAME_IDENTITY
  edges with OPTIONAL MATCH on both sides, so it returns results even
  when group data is incomplete.

- **91**: AD Group Transitive macOS Access -- the most complex cross-domain
  query. It traces a four-hop path: ADUser -[AD_MEMBER_OF]-> ADGroup,
  ADUser -[SAME_IDENTITY]-> User, Application -[PERSISTS_VIA]-> LaunchItem
  -[RUNS_AS]-> User, Application -[HAS_TCC_GRANT]-> TCC_Permission. This
  reveals which AD group memberships transitively grant access to macOS
  TCC-protected resources.

- **92**: APT Group Exposure -- correlates threat groups with the local
  attack surface by joining ThreatGroup -[USES_TECHNIQUE]->
  AttackTechnique <-[MAPS_TO_TECHNIQUE]- Vulnerability <-[AFFECTED_BY]-
  Application. Shows which APT actors could exploit the discovered
  attack surface.

### Vulnerability Integration

The `kerberos` category in `cve_reference.py` maps to three CVEs:

- **CVE-2024-44245:** Kerberos ccache race condition (CVSS 7.0)
- **CVE-2024-49019:** AD Certificate Services abuse, Certifried (CVSS 7.5)
- **CVE-2023-35389:** AD delegation abuse (CVSS 7.5)

These CVEs link to ATT&CK techniques T1558 (Steal or Forge Kerberos
Tickets) and T1556.003 (Pluggable Authentication Modules). The
`import_vulnerabilities.py` category matcher creates AFFECTED_BY edges
from any application with Kerberos-related edges to these CVEs.

## Trade-offs & Decisions

**Username matching is case-insensitive.** AD uses case-insensitive
principal names (RFC 4120), while macOS user names are case-sensitive by
default. The SAME_IDENTITY matching uses `toLower()` on both sides, which
may produce false positives on systems with deliberately case-variant
usernames. This was judged acceptable because the alternative (no matching)
would miss every cross-domain link.

**Principal inference from ccache filenames.** Reading ccache file contents
would reveal the actual Kerberos principal, but Rootstock's design principle
is to never read credential material. Instead, the principal is inferred
from the `krb5cc_<uid>` filename convention via `getpwuid`. This works
reliably on standard macOS systems but will miss custom ccache locations
set via `KRB5CCNAME`.

**BloodHound import is optional.** Not every deployment has SharpHound data.
The `bloodhound_import.py` module runs independently from the main pipeline,
invoked via a separate CLI command. The ADUser and ADGroup nodes it creates
supplement the lightweight AD data the collector gathers natively.

**ADGroup is shared between collector and BloodHound.** Both sources can
create ADGroup nodes (collector from `dsconfigad`, BloodHound from
groups.json). They MERGE on `name`, so the data converges. BloodHound adds
the `object_id` (SID) and `domain` properties that the collector cannot
discover from `dsconfigad` output alone.

**No LDAP queries.** The collector does not perform LDAP queries against
the domain controller. All AD information comes from local system commands
(`dsconfigad`, `dscl`) that reflect the host's cached view of the directory.
This avoids network dependencies and credential requirements while still
capturing the security-relevant binding state.

## Future Work

- **Kerberos ticket content parsing.** With appropriate elevation and user
  consent, parse ccache files to extract actual principal names, ticket
  lifetimes, and encryption types. This would improve accuracy of
  HAS_KERBEROS_CACHE edges and enable detection of over-long ticket
  lifetimes.

- **Constrained delegation detection.** Parse AD delegation attributes
  from SharpHound computer.json data to identify hosts with constrained
  or resource-based constrained delegation, which can be abused for lateral
  movement to macOS targets.

- **Kerberos realm trust mapping.** Parse krb5.conf `[capaths]` and
  `[domain_realm]` sections to model inter-realm trust relationships,
  enabling detection of trust abuse paths.

- **Real-time ccache monitoring.** Integrate with the Endpoint Security
  Framework to detect new ccache creation events, enabling alerting on
  credential theft in real time rather than point-in-time scanning.

- **SharpHound computer node import.** Import computer.json from SharpHound
  to create ADComputer nodes and link them to Rootstock Computer nodes,
  enabling host-level cross-domain correlation.

- **Certificate Services integration.** Import AD CS (Active Directory
  Certificate Services) template data from Certify/Certifried tooling
  to model certificate-based privilege escalation paths that affect
  AD-bound macOS clients (ref: CVE-2024-49019).
