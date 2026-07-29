# Entitlement Categories

Rootstock classifies Apple entitlements into 8 categories for graph inference and
risk scoring. A category is a model input, not proof that the corresponding
capability can be exercised.

## Category Definitions

### 1. `tcc` - TCC Override Entitlements
Entitlements associated with granting or bypassing Transparency, Consent, and
Control (TCC) restrictions. The effective behavior depends on the entitlement
value, signing identity, operating-system version, and runtime context.

Examples:
- `com.apple.private.tcc.allow` - bypass TCC for specific services
- `com.apple.private.tcc.manager` - manage TCC database directly
- `com.apple.private.tcc.allow.overridable` - overridable TCC bypass

Interpretation: Review apps with these entitlements against their expected
signing and TCC behavior. If the graph also contains an injection relationship,
validate capability inheritance separately.

### 2. `injection` - Code Injection Surface
Entitlements that alter code-signing or executable-memory protections.

Examples:
- `com.apple.security.cs.allow-dyld-environment-variables` - allows DYLD_INSERT_LIBRARIES
- `com.apple.security.cs.disable-library-validation` - loads unsigned dylibs
- `com.apple.security.cs.allow-unsigned-executable-memory` - JIT/unsigned code execution
- `com.apple.security.cs.allow-jit` - just-in-time compilation

Interpretation: A matching entitlement combined with TCC grants creates a
modeled path for review. Reproduce the process-loading and permission behavior
before treating the path as exploitable.

### 3. `privilege` - Privilege Escalation
Entitlements that grant elevated system privileges beyond normal app capabilities.

Examples:
- `com.apple.rootless.install` - modify SIP-protected locations
- `com.apple.security.cs.debugger` - attach debugger to other processes
- `com.apple.private.security.clear-library-validation` - clear library validation for targets
- `com.apple.rootless.storage.TCC` - direct TCC database access

Interpretation: These entitlements identify system-level capabilities to
validate against the app's signing identity and runtime behavior.

### 4. `sandbox` - Sandbox Configuration
Entitlements related to App Sandbox configuration and exceptions.

Examples:
- `com.apple.security.app-sandbox` - declares the app is sandboxed
- `com.apple.security.temporary-exception.*` - sandbox escape exceptions
- `com.apple.security.files.user-selected.read-write` - user-selected file access

Interpretation: Review sandbox exceptions against the app's expected function.
Effective access depends on the resolved profile, entitlement values, and
user-selected resources.

### 5. `keychain` - Keychain Access
Entitlements controlling access to Keychain items and groups.

Examples:
- `keychain-access-groups` - declared Keychain access-group identifiers
- `com.apple.keychain.access-groups` - alternative keychain group entitlement

Interpretation: A shared access-group identifier is a candidate relationship.
Validate item ACLs, access-control flags, signing identity, user presence, and
process behavior before concluding that an item can be read.

### 6. `network` - Network Capabilities
Entitlements granting network-related privileges.

Examples:
- `com.apple.developer.networking.vpn.api` - VPN tunnel creation
- `com.apple.developer.networking.networkextension` - network extension framework
- `com.apple.security.network.client` - outbound network access (sandbox)
- `com.apple.security.network.server` - inbound network access (sandbox)

Interpretation: Network entitlements identify available framework capabilities.
They do not prove that a network extension is installed, active, or authorized.

### 7. `icloud` - iCloud Integration
Entitlements enabling iCloud data sync and storage.

Examples:
- `com.apple.developer.icloud-container-identifiers` - iCloud container access
- `com.apple.developer.icloud-services` - iCloud service types (CloudKit, etc.)
- `com.apple.developer.ubiquity-container-identifiers` - ubiquity container sync

Interpretation: iCloud entitlements identify configured container capabilities.
Validate the container identifiers, account state, sync settings, data access,
and process behavior before drawing a cross-device conclusion.

### 8. `other` - Uncategorised
Entitlements that don't fit the above categories. These are typically low-risk
or informational (e.g., app group identifiers, associated domains).

Examples:
- `com.apple.developer.associated-domains` - universal links
- `com.apple.developer.team-identifier` - team ID declaration
- `com.apple.security.application-groups` - app group containers

Risk: Generally low, but context-dependent.

## How Categories Are Used

1. Risk Scoring (`infer_risk_score.py`): Each category contributes a weighted
   factor to the app's composite risk score. `tcc` and `injection` entitlements
   have the highest weights.

2. CVE Matching (`import_vulnerabilities.py`): CVE categories map to entitlement
   categories for vulnerability correlation.

3. Report assembly (`report_assembly.py`): Recommendations are grouped by
   entitlement category.

4. Graph Model (`models.py`): The `EntitlementData.category` field uses these
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
