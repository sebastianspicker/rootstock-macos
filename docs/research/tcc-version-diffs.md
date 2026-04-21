# TCC Version Differences — Research Notes

> Documents known differences in TCC database schema, access restrictions, and
> service identifiers across macOS versions tested with Rootstock.
>
> Last updated: 2026-03-18 (tested on macOS 26.3, Build 25D125)

## Quick Summary

| macOS Version | `access` Table Schema | User TCC.db Access | System TCC.db Access | New Services |
|---|---|---|---|---|
| 14 Sonoma | Baseline (17 columns) | ✅ Normal read | ✅ Requires FDA | None vs. baseline |
| 15 Sequoia | Same as Sonoma | ⚠️ Requires FDA (kernel-enforced) | ✅ Requires FDA | `kTCCServiceGameCenterFriends`, `kTCCServiceWebBrowserPublicKeyCredential` |
| 26 Tahoe | Same as Sonoma | ⚠️ Requires FDA (kernel-enforced) | ✅ Requires FDA | Inherits from Sequoia; specifics TBD |
| < 14 | Older schema | Varies | Varies | Not supported |

---

## macOS 14 Sonoma — Baseline

### Schema: `access` table

```sql
CREATE TABLE access (
    service                              TEXT NOT NULL,
    client                               TEXT NOT NULL,
    client_type                          INTEGER NOT NULL,   -- 0=bundleID 1=path
    auth_value                           INTEGER NOT NULL,   -- 0=deny 1=unknown 2=allow 3=limited
    auth_reason                          INTEGER NOT NULL,   -- 1=prompt 2=settings 3=entitlement 4=MDM 5=system
    auth_version                         INTEGER NOT NULL DEFAULT 1,
    csreq                                BLOB,
    policy_id                            INTEGER,
    indirect_object_identifier_type      INTEGER,
    indirect_object_identifier           TEXT DEFAULT 'UNUSED',
    indirect_object_code_identity        BLOB,
    flags                                INTEGER,
    last_modified                        INTEGER NOT NULL,
    pid                                  INTEGER,
    pid_version                          INTEGER,
    boot_uuid                            TEXT DEFAULT 'UNUSED',
    last_reminded                        INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (service, client, client_type, indirect_object_identifier)
);
```

**Columns Rootstock queries:** `service`, `client`, `client_type`, `auth_value`, `auth_reason`, `last_modified` — the 6 stable columns present in all supported versions.

### Access restrictions (macOS 14)

- **User TCC.db** (`~/Library/Application Support/com.apple.TCC/TCC.db`): Readable with normal user permissions via `SQLITE_OPEN_READONLY`. No special entitlements required.
- **System TCC.db** (`/Library/Application Support/com.apple.TCC/TCC.db`): Requires Full Disk Access (`kTCCServiceSystemPolicyAllFiles`) or root + FDA.

---

## macOS 15 Sequoia — Access Restrictions Tightened

### Schema changes

No column additions or removals from macOS 14. The `access` table schema is identical.

### Access restrictions (macOS 15) — BREAKING CHANGE

Apple tightened TCC.db access at the kernel level in Sequoia:

- **User TCC.db**: `sqlite3_open_v2(..., SQLITE_OPEN_READONLY, ...)` returns `SQLITE_AUTH` even for the process owner's own TCC.db unless the process has Full Disk Access.
- **System TCC.db**: Same as Sonoma (requires FDA).
- **Workarounds**:
  1. Grant FDA to the collector binary via System Settings → Privacy & Security → Full Disk Access.
  2. Run with `sudo` (root process bypasses the restriction).
  3. Sign the binary with `com.apple.private.tcc.allow` (requires Apple developer account with private entitlement approval).
- **Rootstock behavior**: The collector logs a recoverable error and continues with zero TCC grants. The error message on Sequoia/Tahoe includes specific guidance: *"On macOS 15 Sequoia, TCC.db requires Full Disk Access."*

See also: [TD-004 in tech-debt-tracker.md](../exec-plans/tech-debt-tracker.md).

### New TCC services (macOS 15)

| Service Identifier | Display Name | Notes |
|---|---|---|
| `kTCCServiceGameCenterFriends` | Game Center Friends | Access to Game Center friends list (iOS parity feature) |
| `kTCCServiceWebBrowserPublicKeyCredential` | Web Browser Credentials | In-browser passkey/public-key credential access for web browsers |

---

## macOS 26 Tahoe — Year-Based Versioning (2025)

> **Note:** Apple switched to year-based macOS versioning starting in 2025.
> macOS 26 ("Tahoe") corresponds to what was previously planned as "macOS 16".
> `ProcessInfo.processInfo.operatingSystemVersion.majorVersion` returns **26**.
> Darwin kernel reports version 25.x despite the product version being 26.x.

### Verified on: macOS 26.3 (Build 25D125, arm64)

### Schema changes

No schema changes from Sequoia observed. The `access` table has the same 17-column structure as macOS 14/15. `PRAGMA table_info(access)` returns identical column names.

### Access restrictions (macOS 26 Tahoe)

Same as macOS 15 Sequoia — kernel-level enforcement on TCC.db reads. `SQLITE_AUTH` is returned without FDA. The Rootstock error message includes Tahoe-specific guidance.

### New TCC services (macOS 26)

Inherits all services from Sequoia. Tahoe-specific additions have not been publicly documented as of March 2026. The `TCCServiceRegistry` will be updated as services are identified.

---

## Rootstock's Compatibility Strategy

### PRAGMA-based schema detection

`TCCSchemaAdapterFactory.make(for:db:)` calls `PRAGMA table_info(access)` before running any query. This approach:
1. Detects malformed databases (no `access` table → graceful error)
2. Validates that required columns are present
3. Is forward-compatible with future schema additions (new columns are ignored)

### Protocol/strategy pattern

`TCCSchemaAdapter` protocol with concrete implementations (`SonomaTCCSchemaAdapter`, `SequoiaTCCSchemaAdapter`, `TahoeTCCSchemaAdapter`) allows version-specific behavior to be added without if-chains in the reader. Currently all adapters query the same 6 stable columns; future versions can extend their adapter to use new columns.

### Version-aware error messages

When TCC.db can't be opened, the error message is tailored to the running macOS version to give actionable guidance (especially for Sequoia/Tahoe where FDA is mandatory).

---

## Testing Notes

### macOS 14 Sonoma
- Not available for direct testing in this session.
- All TCC unit tests use synthetic fixture databases that replicate the Sonoma schema.
- Behavior is consistent with the documented baseline.

### macOS 15 Sequoia
- Testing confirmed: `SQLITE_AUTH` returned when opening user TCC.db without FDA.
- Fixture-based tests pass on Sequoia.
- Real TCC collection blocked (as expected) without FDA.

### macOS 26 Tahoe (current test machine)
- **Tested on: macOS 26.3, Build 25D125, arm64**
- `SQLITE_AUTH` confirmed when opening user TCC.db without FDA.
- `PRAGMA table_info(access)` returns 17 columns (identical to Sonoma schema).
- All 84 Swift unit tests pass.
- `MacOSVersion.detect()` correctly returns `.tahoe` (`majorVersion == 26`).

---

## Appendix: auth_reason values

| Value | Meaning | Notes |
|---|---|---|
| 1 | User prompted (system dialog) | Standard grant via privacy prompt |
| 2 | User set (System Settings) | Manually toggled in Privacy & Security |
| 3 | System/entitlement-based | App has a private entitlement granting access |
| 4 | MDM policy | Managed via Mobile Device Management |
| 5 | System override | Apple-set for system processes |
