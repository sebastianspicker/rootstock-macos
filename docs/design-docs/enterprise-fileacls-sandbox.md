# File ACL Auditing & Sandbox Profile Analysis

## Motivation

macOS security ultimately rests on file permissions. The TCC database that
controls privacy grants, the Keychain that stores credentials, the sudoers
file that governs privilege escalation, and the authorization database that
defines system authentication policy are all regular files protected by
POSIX permissions and optional ACL entries. If any of these files are
writable by a non-root user, the entire security model collapses. An
attacker who can write to TCC.db can grant themselves Full Disk Access.
An attacker who can modify sudoers can gain passwordless root.

Traditional macOS security audits check permissions on a few well-known
files, but miss the broader picture. Rootstock's file ACL auditing module
systematically scans every security-critical path, records the full
permission state (owner, group, mode, ACL entries, SIP protection,
writability analysis), and feeds this into the graph as `CriticalFile`
nodes with `CAN_WRITE` edges to applications that could exploit weak
permissions.

The sandbox subsystem addresses the complementary problem: what can a
sandboxed application actually do? Apple's App Sandbox restricts file,
network, mach service, and IOKit access through SBPL (Sandbox Profile
Language) rules and entitlement-based exceptions. Rootstock's sandbox
analysis extracts these rules from both entitlements and system SBPL
profiles, creating `SandboxProfile` nodes that quantify the effective
attack surface of each sandboxed application.

Quarantine (Gatekeeper) analysis completes the picture by tracking which
applications have the `com.apple.quarantine` extended attribute, whether
they were user-approved, and whether they were translocated -- all signals
that indicate whether an application bypassed or was vetted through
Apple's code trust chain.

## Design Overview

```
┌───────────────────────────────────────────────────────────────┐
│                     Swift Collector                           │
│                                                               │
│  FileACLDataSource            SandboxDataSource               │
│  ─ Scan critical paths        ─ Entitlement-derived rules     │
│  ─ Read POSIX attrs           ─ System SBPL profile parsing   │
│  ─ Parse ls -le ACLs          ─ SandboxProfileParser (regex)  │
│  ─ Check SIP protection                                       │
│  ─ Writability analysis       QuarantineDataSource            │
│                               ─ Read com.apple.quarantine     │
│                               ─ Parse flag/timestamp/agent    │
└───────────────────┬───────────────────────┬───────────────────┘
                    │ scan.json             │
┌───────────────────▼───────────────────────▼───────────────────┐
│                    Python Graph Pipeline                       │
│                                                               │
│  import_nodes_security.py (FileACL import)                    │
│  ─ MERGE CriticalFile nodes                                   │
│  ─ PROTECTS edges (SIP → CriticalFile)                        │
│                                                               │
│  import_nodes_core.py (SandboxProfile + Quarantine import)    │
│  ─ MERGE SandboxProfile nodes                                 │
│  ─ HAS_SANDBOX_PROFILE edges                                  │
│  ─ Set quarantine properties on Application nodes             │
│                                                               │
│  infer_file_acl.py                                            │
│  ─ CAN_WRITE edges (Application → CriticalFile)              │
│  ─ CAN_MODIFY_TCC edges (Application → TCC_Permission)       │
│                                                               │
│  infer_sandbox.py                                             │
│  ─ Sandbox-aware edge filtering                               │
│                                                               │
│  infer_quarantine.py                                          │
│  ─ BYPASSED_GATEKEEPER edges                                  │
└───────────────────────────────────────────────────────────────┘
```

## Implementation Details

### Collector: FileACLDataSource

**Location:** `collector/Sources/FileACLs/FileACLDataSource.swift`

The data source defines a static list of critical paths grouped by
semantic category:

| Category | Paths |
|----------|-------|
| `tcc_database` | `~/Library/Application Support/com.apple.TCC/TCC.db`, `/Library/Application Support/com.apple.TCC/TCC.db` |
| `keychain` | `~/Library/Keychains/login.keychain-db`, `/Library/Keychains/System.keychain` |
| `sudoers` | `/etc/sudoers`, plus all files in `/etc/sudoers.d/` |
| `ssh_config` | `/etc/ssh/sshd_config` |
| `launch_agent_dir` | `~/Library/LaunchAgents/`, `/Library/LaunchAgents/` |
| `launch_daemon_dir` | `/Library/LaunchDaemons/` |
| `authorization_db` | `/etc/authorization` |

For each path, the collector records:

- **Owner and group** from `FileManager.attributesOfItem`
- **POSIX mode** as an octal string (e.g., `644`)
- **Extended ACL entries** parsed from `ls -led` output. The parser strips
  the leading `N: ` prefix from each ACL line, extracting entries like
  `user:john allow write,append`
- **SIP protection status** based on known SIP-protected path prefixes
  (`/System/`, `/usr/lib/`, `/usr/bin/`, `/usr/sbin/`)
- **Writability analysis** via `checkWritableByNonRoot()`, which evaluates
  three conditions:
  1. World-writable bit set (`mode & 0o002`)
  2. Owner is not root and has write permission (`mode & 0o200`)
  3. Any ACL entry contains both `allow` and `write`

For directory paths (LaunchAgents, LaunchDaemons), the collector also
enumerates `.plist` files within the directory and checks each one
individually. This catches writable LaunchAgent plists that could be
replaced with malicious payloads.

The sudoers special case also scans `/etc/sudoers.d/` for include files,
since sudoers rules are commonly split across multiple files.

Tilde paths are expanded via `NSString.expandingTildeInPath` to handle
the current user's home directory.

### Collector: SandboxDataSource & SandboxProfileParser

**Location:** `collector/Sources/Sandbox/SandboxDataSource.swift`,
`collector/Sources/Sandbox/SandboxProfileParser.swift`

The sandbox analysis uses a two-source approach:

**Source 1: Entitlement-derived rules.** For each sandboxed application,
the collector intersects the application's entitlement list with known
sandbox-related entitlement sets:

- File read entitlements (`com.apple.security.files.user-selected.read-only`, etc.)
- File write entitlements (`com.apple.security.files.user-selected.read-write`, etc.)
- Network entitlements (`com.apple.security.network.client`, etc.)
- Mach lookup entitlements (`com.apple.security.temporary-exception.mach-lookup.global-name`, etc.)
- IOKit entitlements (`com.apple.security.temporary-exception.iokit-user-client-class`)

Each matched entitlement is recorded as a rule in the corresponding
category.

**Source 2: System SBPL profiles.** The collector looks for
`/System/Library/Sandbox/Profiles/<bundleId>.sb` files. If found, the
`SandboxProfileParser` parses the SBPL text using regex extraction of
`(allow|deny <operation> ...)` directives. The parser recognizes five
operation categories:

- `file-read*` operations map to fileReadRules
- `file-write*` operations map to fileWriteRules
- `mach-lookup` and `mach-register` map to machLookupRules
- `network*` operations map to networkRules
- `iokit*` operations map to iokitRules

The two rule sets are merged into a single `SandboxProfile` with computed
properties:
- `exceptionCount`: number of sandbox exceptions from the application's entitlements
- `hasUnconstrainedNetwork`: whether the app has `com.apple.security.network.client` or `.server`
- `hasUnconstrainedFileRead`: whether the app has `com.apple.security.files.all`

**Design constraint:** Apple's compiled sandbox profiles use a proprietary
binary format that is not publicly documented. The SBPL parser only works
with text-based system profiles in `/System/Library/Sandbox/Profiles/`.
User-level app sandbox profiles embedded in the application binary are not
accessible for parsing. The entitlement-based approach compensates for this
limitation by inferring sandbox permissions from the entitlements that
control them.

### Collector: QuarantineDataSource

**Location:** `collector/Sources/Quarantine/QuarantineDataSource.swift`

Reads the `com.apple.quarantine` extended attribute from each application
bundle path using `getxattr`. The attribute value is a semicolon-delimited
string with four fields:

```
QFLAG;TIMESTAMP;AGENT_BUNDLE_ID;UUID
```

Example: `0083;5f3b3c00;com.apple.Safari;12345678-...`

The parser extracts:
- **Flags** (hex): `0x0040` = user approved, `0x0020` = was translocated
- **Timestamp** (hex epoch seconds): converted to ISO 8601
- **Agent bundle ID**: the application that downloaded the file (e.g.,
  `com.apple.Safari`, `com.google.Chrome`)

An application without the quarantine attribute was either installed via
a trusted channel (App Store, MDM) or had its quarantine flag stripped --
the latter is a security concern that the `infer_quarantine.py` module
flags with `BYPASSED_GATEKEEPER` edges.

### Graph Import

**CriticalFile nodes** are created by `import_nodes_security.py` with the
full permission metadata. The `PROTECTS` edge is created from SIP to
CriticalFile for files under SIP-protected paths.

**SandboxProfile nodes** are created by `import_nodes_core.py` with all
rule arrays as properties. The `HAS_SANDBOX_PROFILE` edge links each
Application to its SandboxProfile.

**Quarantine data** is stored directly on Application nodes as properties:
`has_quarantine_flag`, `quarantine_agent`, `quarantine_timestamp`,
`was_user_approved`, `was_translocated`.

### Inference

**infer_file_acl.py** creates two edge types:

1. `CAN_WRITE`: From applications with injection methods to CriticalFile
   nodes where `is_writable_by_non_root = true`. This represents the
   attack path: an injectable application could be hijacked to modify a
   security-critical file.

2. `CAN_MODIFY_TCC`: A specialized edge from writable-TCC-db applications
   to the corresponding TCC_Permission nodes. This models the ultimate
   privilege escalation: writing to TCC.db to grant arbitrary TCC
   permissions.

**infer_sandbox.py** adjusts edge weights and classifications based on
sandbox containment. Applications with effective sandbox profiles have
their attack surface reduced in tier classification.

**infer_quarantine.py** creates `BYPASSED_GATEKEEPER` edges for non-system
applications that lack the quarantine attribute and are not signed by
Apple, indicating they may have circumvented Gatekeeper verification.

## Graph Model Impact

### Node Types Added

| Label | Key Property | Source |
|-------|-------------|--------|
| `CriticalFile` | `path` | FileACLDataSource |
| `SandboxProfile` | `bundle_id` | SandboxDataSource |

### Relationships Added

| Relationship | From | To | Meaning |
|-------------|------|-----|---------|
| `CAN_WRITE` | Application | CriticalFile | Injectable app can modify critical file |
| `PROTECTS` | SIP | CriticalFile | File is under SIP protection |
| `CAN_MODIFY_TCC` | Application | TCC_Permission | App can modify TCC database |
| `HAS_SANDBOX_PROFILE` | Application | SandboxProfile | App's sandbox rules |
| `BYPASSED_GATEKEEPER` | Application | Computer | App lacks quarantine verification |

### Properties on CriticalFile

`path`, `owner`, `group`, `mode`, `acl_entries` (list), `is_sip_protected`,
`is_writable_by_non_root`, `category`

### Properties on SandboxProfile

`bundle_id`, `profile_source`, `file_read_rules` (list),
`file_write_rules` (list), `mach_lookup_rules` (list),
`network_rules` (list), `iokit_rules` (list), `exception_count`,
`has_unconstrained_network`, `has_unconstrained_file_read`

### Properties on Application (Quarantine)

`has_quarantine_flag`, `quarantine_agent`, `quarantine_timestamp`,
`was_user_approved`, `was_translocated`

### Cypher Queries

- **86**: Sandbox escape vectors -- applications without sandbox that have
  injection methods
- **87**: Sandbox exception audit -- sandboxed apps ranked by exception count
- **88**: Unquarantined apps -- non-system apps missing quarantine attribute
- **89**: Quarantine bypass with TCC -- unquarantined apps that hold TCC grants

## Trade-offs & Decisions

**Static critical path list vs. dynamic discovery.** The critical paths
are hardcoded rather than discovered dynamically. Dynamic discovery (e.g.,
scanning all files referenced by system daemons) would be more
comprehensive but would dramatically increase scan time and produce an
overwhelming number of nodes. The static list covers the highest-impact
targets based on real-world macOS privilege escalation research.

**SBPL parsing is regex-based, not a full parser.** SBPL is a Scheme-like
language with nested S-expressions, closures, and macro expansion.
Building a full SBPL parser would be a significant engineering effort and
fragile against Apple's undocumented format changes. The regex approach
captures the top-level allow/deny directives, which contain the
security-relevant permission grants. Nested conditional expressions within
filter clauses are captured as raw text, not parsed structurally.

**Quarantine agent as a string, not a relationship.** The quarantine agent
(the application that downloaded the file) is stored as a string property
rather than as an edge to an Application node. This avoids creating
spurious edges when the downloading application is not present in the
scanned system (e.g., a browser that has since been uninstalled).

**ACL parsing via ls -le rather than direct API.** The collector shells
out to `ls -led` to read ACL entries rather than using the POSIX ACL C
API (`acl_get_file`). This was chosen because the `ls` output format is
stable across macOS versions and easier to parse, while the C API
requires complex memory management in Swift without Foundation wrappers.
The trade-off is an external process invocation per file.

**SIP detection is prefix-based.** Rather than querying the actual SIP
configuration (which requires `csrutil status` and root), SIP protection
is inferred from well-known path prefixes. This is correct for default
SIP configurations but will not detect custom SIP exclusions added via
`csrutil authenticated-root disable` or recovery mode modifications.

## Future Work

- **Extended attribute scanning beyond quarantine.** Other security-relevant
  xattrs include `com.apple.rootless` (SIP), `com.apple.metadata:kMDItemDownloadedDate`,
  and `com.apple.macl` (managed app launch control). Adding these would
  provide a more complete picture of file provenance and protection.

- **Full SBPL parser.** Implement a proper S-expression parser for SBPL
  profiles that can handle nested conditionals, `require-any`/`require-all`
  combinators, and macro expansion. This would enable precise sandbox
  escape analysis by computing the effective permission set.

- **Runtime sandbox violation monitoring.** Integrate with the sandbox
  violation syslog (`sandboxd` messages) to detect applications that are
  hitting sandbox boundaries, which may indicate exploitation attempts or
  sandbox configuration issues.

- **File integrity monitoring integration.** Compare collected file ACL
  state against a known-good baseline to detect unauthorized permission
  changes. This would enable detection of post-compromise persistence
  via ACL modification.

- **Launch constraint analysis.** Parse macOS 14+ launch constraints
  (stored as DER-encoded trust caches) to model which applications are
  restricted from launching other applications, adding another layer to
  the sandbox analysis.

- **Notarization ticket verification.** Verify notarization tickets against
  Apple's notarization service to detect revoked notarizations, which
  indicate applications that Apple has determined to be malicious after
  initial approval.
