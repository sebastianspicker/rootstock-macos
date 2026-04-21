# TCC Internals — Research Notes

> Reference for the Collector Engineer agent when implementing the TCC parser.
> Sources: Apple Platform Security Guide, HackTricks, Wojciech Reguła research.

## TCC Database Locations

| Database | Path | Requires |
|---|---|---|
| User-level | `~/Library/Application Support/com.apple.TCC/TCC.db` | Normal user access |
| System-level | `/Library/Application Support/com.apple.TCC/TCC.db` | Full Disk Access (FDA) |
| MDM-managed | Entries in system DB with `auth_reason = 4` (MDM policy) | FDA |

Both are SQLite3 databases.

## Schema: `access` table (macOS 14 Sonoma)

```sql
CREATE TABLE access (
    service        TEXT NOT NULL,     -- TCC service identifier
    client         TEXT NOT NULL,     -- Bundle ID or path
    client_type    INTEGER NOT NULL,  -- 0 = bundle ID, 1 = absolute path
    auth_value     INTEGER NOT NULL,  -- Authorization status
    auth_reason    INTEGER NOT NULL,  -- How the authorization was set
    auth_version   INTEGER NOT NULL,
    csreq          BLOB,             -- Code signing requirement (binary)
    policy_id      INTEGER,
    indirect_object_identifier_type INTEGER,
    indirect_object_identifier      TEXT DEFAULT 'UNUSED',
    indirect_object_code_identity   BLOB,
    flags          INTEGER,
    last_modified  INTEGER NOT NULL,  -- Unix timestamp
    pid            INTEGER,           -- PID at time of grant (if applicable)
    pid_version    INTEGER,
    boot_uuid      TEXT DEFAULT 'UNUSED',
    last_reminded  INTEGER NOT NULL DEFAULT 0
);
```

## auth_value meanings

| Value | Meaning | Graph edge property |
|---|---|---|
| 0 | Denied | `allowed: false` |
| 1 | Unknown | skip |
| 2 | Allowed | `allowed: true` |
| 3 | Limited (e.g., selected photos only) | `allowed: true, limited: true` |

## auth_reason meanings

| Value | Meaning |
|---|---|
| 1 | User set (via system prompt) |
| 2 | User set (via System Preferences / Settings) |
| 3 | System set (entitlement-based) |
| 4 | MDM policy |
| 5 | System set (implicit / override) |

## Important TCC service identifiers

| Identifier | Display Name | Why it matters |
|---|---|---|
| `kTCCServiceSystemPolicyAllFiles` | Full Disk Access | Access to all files including TCC.db itself |
| `kTCCServiceAccessibility` | Accessibility | Can control other apps, key logging |
| `kTCCServiceScreenCapture` | Screen Recording | Can capture screen content |
| `kTCCServiceMicrophone` | Microphone | Audio surveillance |
| `kTCCServiceCamera` | Camera | Visual surveillance |
| `kTCCServiceSystemPolicyDesktopFolder` | Desktop | Access to ~/Desktop |
| `kTCCServiceSystemPolicyDocumentsFolder` | Documents | Access to ~/Documents |
| `kTCCServiceSystemPolicyDownloadsFolder` | Downloads | Access to ~/Downloads |
| `kTCCServiceAppleEvents` | Automation | Can send Apple Events to other apps |
| `kTCCServiceListenEvent` | Input Monitoring | Can monitor keyboard/mouse input |
| `kTCCServicePostEvent` | (deprecated) | Can inject keyboard/mouse events |
| `kTCCServiceSystemPolicyRemovableVolumes` | Removable Volumes | Access to USB drives etc. |
| `kTCCServiceSystemPolicyNetworkVolumes` | Network Volumes | Access to network shares |
| `kTCCServiceEndpointSecurityClient` | Endpoint Security | Can use ESF APIs |

## csreq (Code Signing Requirement) field

The `csreq` blob is a compiled code signing requirement in binary format.
It can be decoded with `csreq -r- -t < blob.bin` but for our purposes we
primarily match via `client` (bundle ID) and verify against the app's
actual code signing identity during graph import.

**Key insight for attack paths:** The csreq often does NOT include version
information. This means an older, less secure version of the same app
(same bundle ID, same team ID) can inherit TCC grants from the current version.

## Known Caveats

- On macOS 15 (Sequoia), Apple added additional protections around TCC.db access.
  The user-level DB may require additional entitlements to read in some configurations.
- The TCC daemon (`tccd`) caches state in memory. The database reflects persistent
  state but may lag behind runtime state.
- iCloud Keychain items are NOT stored in the local TCC database.
