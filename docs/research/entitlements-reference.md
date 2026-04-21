# Security-Critical Entitlements — Reference

> Reference for the Collector Engineer when classifying entitlements by security impact.
> These entitlements represent the highest-value targets for attack path analysis.

## Injection-Enabling Entitlements

These make an app a viable injection target:

| Entitlement | Effect | Attack Relevance |
|---|---|---|
| `com.apple.security.cs.allow-dyld-environment-variables` | Allows DYLD_* env vars | Enables DYLD_INSERT_LIBRARIES injection even with hardened runtime |
| `com.apple.security.cs.disable-library-validation` | Disables library validation | Allows loading unsigned/differently-signed dylibs |
| `com.apple.security.cs.allow-unsigned-executable-memory` | Allows JIT | Enables runtime code generation, potential for code injection |
| `com.apple.security.cs.disable-executable-page-protection` | Disables W^X | Allows writable+executable memory pages |

## TCC-Related Private Entitlements

These grant TCC access without user consent:

| Entitlement | Effect | Attack Relevance |
|---|---|---|
| `com.apple.private.tcc.allow` | Bypass TCC for listed services | App silently gets TCC access — if injectable, attacker inherits |
| `com.apple.private.tcc.manager` | Can modify TCC database | Can grant TCC permissions to other apps |
| `com.apple.private.tcc.manager.check-by-audit-token` | TCC check bypass | Can check TCC without standard validation |

## Privilege-Related Entitlements

| Entitlement | Effect | Attack Relevance |
|---|---|---|
| `com.apple.security.get-task-allow` | Allows task_for_pid | Debugger can attach; enables memory inspection |
| `com.apple.security.cs.debugger` | Debugger capability | Can debug other processes |
| `com.apple.rootless.install` | Can install to SIP-protected locations | Potential SIP bypass vector |
| `com.apple.rootless.storage.corestorage` | Can modify CoreStorage volumes | Disk-level access |

## Keychain-Related Entitlements

| Entitlement | Effect | Attack Relevance |
|---|---|---|
| `keychain-access-groups` | Defines shared Keychain groups | Determines which Keychain items the app can access |
| `com.apple.security.smartcard` | Smart card / token access | Can access hardware tokens |

## Sandbox-Related Entitlements

| Entitlement | Effect | Attack Relevance |
|---|---|---|
| `com.apple.security.app-sandbox` | App is sandboxed | Limits what injected code can do |
| `com.apple.security.temporary-exception.*` | Sandbox exceptions | Weakens sandbox; each exception is a potential path |
| `com.apple.security.network.client` | Outbound network access | Can exfiltrate data |
| `com.apple.security.network.server` | Inbound network access | Can receive commands |
| `com.apple.security.files.user-selected.read-write` | User-selected file access | Broader than default sandbox |

## Classification for Graph Model

When the collector encounters an entitlement, classify it:

```swift
enum EntitlementCategory: String, Codable {
    case tcc          // com.apple.private.tcc.*
    case injection    // cs.allow-dyld-*, cs.disable-library-validation
    case privilege    // get-task-allow, rootless.*, debugger
    case sandbox      // app-sandbox, temporary-exception.*
    case keychain     // keychain-access-groups
    case network      // network.client, network.server
    case other
}

var isSecurityCritical: Bool {
    switch self {
    case .tcc, .injection, .privilege: return true
    default: return false
    }
}
```
