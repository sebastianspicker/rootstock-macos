# Entitlement Categories

Rootstock classifies Apple entitlements into 8 categories based on their security impact.
These categories drive the inference engine's risk scoring and attack path discovery.

## Category Definitions

### 1. `tcc` — TCC Override Entitlements
Entitlements that grant or bypass Transparency, Consent, and Control (TCC) restrictions.
These are the highest-impact entitlements — they can silently access protected resources.

**Examples:**
- `com.apple.private.tcc.allow` — bypass TCC for specific services
- `com.apple.private.tcc.manager` — manage TCC database directly
- `com.apple.private.tcc.allow.overridable` — overridable TCC bypass

**Risk:** Apps with these entitlements can access camera, microphone, contacts, etc.
without user consent prompts. If injectable, an attacker inherits this access.

### 2. `injection` — Code Injection Surface
Entitlements that weaken code signing protections, enabling code injection attacks.

**Examples:**
- `com.apple.security.cs.allow-dyld-environment-variables` — allows DYLD_INSERT_LIBRARIES
- `com.apple.security.cs.disable-library-validation` — loads unsigned dylibs
- `com.apple.security.cs.allow-unsigned-executable-memory` — JIT/unsigned code execution
- `com.apple.security.cs.allow-jit` — just-in-time compilation

**Risk:** An injectable app with TCC grants creates a privilege escalation path.
The injection entitlement is the enabler; the TCC grant is the payload.

### 3. `privilege` — Privilege Escalation
Entitlements that grant elevated system privileges beyond normal app capabilities.

**Examples:**
- `com.apple.rootless.install` — modify SIP-protected locations
- `com.apple.security.cs.debugger` — attach debugger to other processes
- `com.apple.private.security.clear-library-validation` — clear library validation for targets
- `com.apple.rootless.storage.TCC` — direct TCC database access

**Risk:** These entitlements can escalate from app-level to system-level access.

### 4. `sandbox` — Sandbox Configuration
Entitlements related to App Sandbox configuration and exceptions.

**Examples:**
- `com.apple.security.app-sandbox` — declares the app is sandboxed
- `com.apple.security.temporary-exception.*` — sandbox escape exceptions
- `com.apple.security.files.user-selected.read-write` — user-selected file access

**Risk:** Sandbox exceptions weaken containment. An app with broad file access
exceptions combined with injection vectors exposes more of the filesystem.

### 5. `keychain` — Keychain Access
Entitlements controlling access to Keychain items and groups.

**Examples:**
- `keychain-access-groups` — which Keychain access groups the app can read
- `com.apple.keychain.access-groups` — alternative keychain group entitlement

**Risk:** Apps sharing a Keychain access group can read each other's stored
credentials. An injectable app in a sensitive group exposes all group secrets.

### 6. `network` — Network Capabilities
Entitlements granting network-related privileges.

**Examples:**
- `com.apple.developer.networking.vpn.api` — VPN tunnel creation
- `com.apple.developer.networking.networkextension` — network extension framework
- `com.apple.security.network.client` — outbound network access (sandbox)
- `com.apple.security.network.server` — inbound network access (sandbox)

**Risk:** Network entitlements enable data exfiltration paths and network-level attacks.

### 7. `icloud` — iCloud Integration
Entitlements enabling iCloud data sync and storage.

**Examples:**
- `com.apple.developer.icloud-container-identifiers` — iCloud container access
- `com.apple.developer.icloud-services` — iCloud service types (CloudKit, etc.)
- `com.apple.developer.ubiquity-container-identifiers` — ubiquity container sync

**Risk:** Injectable apps with iCloud entitlements can exfiltrate data via iCloud
sync to all devices enrolled in the same Apple ID — a cross-device data leak.

### 8. `other` — Uncategorised
Entitlements that don't fit the above categories. These are typically low-risk
or informational (e.g., app group identifiers, associated domains).

**Examples:**
- `com.apple.developer.associated-domains` — universal links
- `com.apple.developer.team-identifier` — team ID declaration
- `com.apple.security.application-groups` — app group containers

**Risk:** Generally low, but context-dependent.

## How Categories Are Used

1. **Risk Scoring** (`infer_risk_score.py`): Each category contributes a weighted
   factor to the app's composite risk score. `tcc` and `injection` entitlements
   have the highest weights.

2. **CVE Matching** (`import_vulnerabilities.py`): CVE categories map to entitlement
   categories for vulnerability correlation.

3. **Report Generation** (`report_assembly.py`): Recommendations are grouped by
   entitlement category.

4. **Graph Model** (`models.py`): The `EntitlementData.category` field uses these
   categories as a Literal type enum.

## Classification Logic

Entitlement classification is performed by the Swift collector in
`EntitlementDataSource.swift`. The classifier checks entitlement name prefixes:

| Prefix | Category |
|--------|----------|
| `com.apple.private.tcc` | `tcc` |
| `com.apple.security.cs.allow-dyld` | `injection` |
| `com.apple.security.cs.disable-library` | `injection` |
| `com.apple.security.cs.allow-unsigned` | `injection` |
| `com.apple.security.cs.allow-jit` | `injection` |
| `com.apple.rootless` | `privilege` |
| `com.apple.security.cs.debugger` | `privilege` |
| `com.apple.security.app-sandbox` | `sandbox` |
| `com.apple.security.temporary-exception` | `sandbox` |
| `keychain-access-groups` | `keychain` |
| `com.apple.developer.networking` | `network` |
| `com.apple.developer.icloud` | `icloud` |
| `com.apple.developer.ubiquity` | `icloud` |
| *(everything else)* | `other` |
