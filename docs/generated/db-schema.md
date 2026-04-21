# Rootstock Graph Database Schema

> Cross-reference: [ARCHITECTURE.md — Graph Model](../../ARCHITECTURE.md#graph-model)
>
> This schema is implemented in:
> - Constraints and indexes: `graph/schema/init-schema.cypher`
> - TCC seed data: `graph/schema/seed-tcc-services.cypher`
> - Schema application: `graph/setup.py`

---

## Node Labels

### `Application`

Represents a discovered macOS `.app` bundle.

| Property | Type | Required | Description |
|---|---|---|---|
| `bundle_id` | String | **Yes** (unique) | CFBundleIdentifier (e.g., `com.googlecode.iterm2`) |
| `name` | String | **Yes** | CFBundleName or display name |
| `path` | String | **Yes** | Absolute path (e.g., `/Applications/iTerm.app`) |
| `version` | String | No | CFBundleShortVersionString |
| `team_id` | String | No | Code signing team identifier (nil for platform binaries) |
| `hardened_runtime` | Boolean | **Yes** | CS_RUNTIME flag (0x10000) set |
| `library_validation` | Boolean | **Yes** | Effective library validation enabled |
| `is_electron` | Boolean | **Yes** | Contains Electron Framework (heuristic) |
| `is_system` | Boolean | **Yes** | Located under `/System/` or `/usr/` |
| `signed` | Boolean | **Yes** | Has a valid code signature |
| `scan_id` | String | **Yes** | UUID of the collector scan that produced this node |

**Indexes:** `hardened_runtime`, `library_validation`, `is_electron`, `is_system`

---

### `TCC_Permission`

Represents a TCC service category. Pre-seeded at schema initialization.

| Property | Type | Required | Description |
|---|---|---|---|
| `service` | String | **Yes** (unique) | TCC service identifier (e.g., `kTCCServiceAccessibility`) |
| `display_name` | String | **Yes** | Human-readable name (e.g., `Accessibility`) |

**Pre-seeded services (24):**

| Service | Display Name |
|---|---|
| `kTCCServiceSystemPolicyAllFiles` | Full Disk Access |
| `kTCCServiceAccessibility` | Accessibility |
| `kTCCServiceScreenCapture` | Screen Recording |
| `kTCCServiceMicrophone` | Microphone |
| `kTCCServiceCamera` | Camera |
| `kTCCServiceAppleEvents` | Automation |
| `kTCCServiceListenEvent` | Input Monitoring |
| `kTCCServicePostEvent` | Keyboard Event Injection |
| `kTCCServiceSystemPolicyDesktopFolder` | Desktop Folder |
| `kTCCServiceSystemPolicyDocumentsFolder` | Documents Folder |
| `kTCCServiceSystemPolicyDownloadsFolder` | Downloads Folder |
| `kTCCServiceSystemPolicyRemovableVolumes` | Removable Volumes |
| `kTCCServiceSystemPolicyNetworkVolumes` | Network Volumes |
| `kTCCServiceEndpointSecurityClient` | Endpoint Security |
| `kTCCServiceLocation` | Location Services |
| `kTCCServicePhotos` | Photos |
| `kTCCServiceContacts` | Contacts |
| `kTCCServiceCalendar` | Calendar |
| `kTCCServiceReminders` | Reminders |
| `kTCCServiceAddressBook` | Address Book |
| `kTCCServiceSpeechRecognition` | Speech Recognition |
| `kTCCServiceBluetoothAlways` | Bluetooth |
| `kTCCServiceUserTracking` | Tracking |
| `kTCCServiceFocusStatus` | Focus Status |

---

### `Entitlement`

Represents a code signing entitlement key.

| Property | Type | Required | Description |
|---|---|---|---|
| `name` | String | **Yes** (unique) | Entitlement key (e.g., `com.apple.security.cs.allow-dyld-environment-variables`) |
| `is_private` | Boolean | **Yes** | `true` if key starts with `com.apple.private.` |
| `category` | String | **Yes** | One of: `tcc`, `injection`, `privilege`, `sandbox`, `keychain`, `network`, `other` |

**Indexes:** `is_private`, `category`

---

### `User`

Represents a local macOS user account.

| Property | Type | Required | Description |
|---|---|---|---|
| `name` | String | **Yes** (unique) | Short username |
| `uid` | Integer | **Yes** | Unix user ID |
| `is_admin` | Boolean | **Yes** | Member of admin group |
| `home` | String | **Yes** | Home directory path |
| `type` | String | **Yes** | One of: `local`, `network`, `mobile` |

---

### `XPC_Service`

Represents an XPC service endpoint (LaunchDaemon or LaunchAgent).

| Property | Type | Required | Description |
|---|---|---|---|
| `label` | String | **Yes** (unique) | Launchd label (e.g., `com.apple.diskarbitrationd`) |
| `path` | String | **Yes** | Path to the plist |
| `program` | String | **Yes** | Executable path |
| `user` | String | No | RunAtLoad user context |
| `type` | String | **Yes** | One of: `daemon`, `agent` |

---

### `LaunchItem`

Represents a persistence mechanism (LaunchDaemon, LaunchAgent, or login item).

| Property | Type | Required | Description |
|---|---|---|---|
| `label` | String | **Yes** (unique) | Launchd label or login item identifier |
| `path` | String | **Yes** | Path to the plist or application |
| `type` | String | **Yes** | One of: `daemon`, `agent`, `login_item` |
| `program` | String | **Yes** | Executable path |
| `run_at_load` | Boolean | **Yes** | Whether the item runs at login/boot |

---

### `Keychain_Item` *(Phase 3)*

Represents a Keychain item's metadata (never secret values).

| Property | Type | Required | Description |
|---|---|---|---|
| `label` | String | **Yes** | Item label |
| `kind` | String | **Yes** | One of: `generic_password`, `internet_password`, `certificate`, `key` |
| `service` | String | No | Keychain service attribute |

---

### `MDM_Profile` *(Phase 3)*

Represents an installed MDM configuration profile.

| Property | Type | Required | Description |
|---|---|---|---|
| `identifier` | String | **Yes** | Profile identifier |
| `display_name` | String | **Yes** | Human-readable name |
| `organization` | String | No | Issuing organization |
| `install_date` | String | No | ISO 8601 install timestamp |

---

## Relationship Types

### Direct Relationships (from collector JSON)

| Relationship | Source → Target | Properties | Description |
|---|---|---|---|
| `HAS_TCC_GRANT` | Application → TCC_Permission | `allowed: Bool`, `auth_reason: String?` | App has a TCC database entry |
| `HAS_ENTITLEMENT` | Application → Entitlement | — | App declares this entitlement |
| `SIGNED_BY` | Application → Application | `team_id: String` | Apps sharing the same signing team |
| `COMMUNICATES_WITH` | Application → XPC_Service | — | App has registered XPC service |
| `PERSISTS_VIA` | Application → LaunchItem | — | App registers a persistence mechanism |
| `OWNS` | User → Application | — | User is the owner of the app |
| `HAS_KEYCHAIN` | User → Keychain_Item | — | User's keychain contains this item |
| `RUNS_AS` | LaunchItem → User | — | Daemon/agent runs in user context |
| `CONFIGURES` | MDM_Profile → TCC_Permission | — | MDM profile manages this TCC policy |
| `CAN_READ_KEYCHAIN` | Application → Keychain_Item | — | App has keychain ACL access |

### Inferred Relationships (computed at import time)

| Relationship | Inference Rule |
|---|---|
| `CAN_INJECT_INTO` | Target has `library_validation = false` AND (`hardened_runtime = false` OR has `com.apple.security.cs.allow-dyld-environment-variables` entitlement) |
| `CHILD_INHERITS_TCC` | Source is Electron AND has TCC grants (children via `ELECTRON_RUN_AS_NODE` inherit parent TCC) |
| `CAN_SEND_APPLE_EVENT` | Source has `com.apple.private.tcc.allow` entitlement OR explicit `kTCCServiceAppleEvents` grant |

---

## Constraints Summary

| Constraint | Label | Property |
|---|---|---|
| `application_bundle_id` | Application | `bundle_id` |
| `tcc_permission_service` | TCC_Permission | `service` |
| `entitlement_name` | Entitlement | `name` |
| `xpc_service_label` | XPC_Service | `label` |
| `user_name` | User | `name` |
| `launch_item_label` | LaunchItem | `label` |

## Index Summary

| Index | Label | Property |
|---|---|---|
| `application_hardened_runtime` | Application | `hardened_runtime` |
| `application_library_validation` | Application | `library_validation` |
| `application_is_electron` | Application | `is_electron` |
| `application_is_system` | Application | `is_system` |
| `entitlement_is_private` | Entitlement | `is_private` |
| `entitlement_category` | Entitlement | `category` |
