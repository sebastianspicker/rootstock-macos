# Entitlement categories

The collector groups entitlement names into eight categories. These labels help
you navigate the graph; they do not establish what an application can do at
runtime. Entitlement values, signing identity, macOS version, and process
context still matter.

The rules below match
[`EntitlementClassifier.swift`](../../collector/Sources/Entitlements/EntitlementClassifier.swift).
Rules are checked in order. A name that matches none of them becomes `other`.

## Classification rules

| Category | Exact names or prefixes |
| --- | --- |
| `tcc` | Names starting with `com.apple.private.tcc.` |
| `injection` | `com.apple.security.cs.allow-dyld-environment-variables`, `com.apple.security.cs.disable-library-validation`, `com.apple.security.cs.allow-unsigned-executable-memory`, `com.apple.security.cs.disable-executable-page-protection` |
| `privilege` | Names starting with `com.apple.rootless.`, plus `com.apple.security.get-task-allow`, `com.apple.security.cs.debugger`, `com.apple.developer.endpoint-security.client`, `com.apple.developer.networking.vpn.api`, and `com.apple.developer.networking.networkextension` |
| `sandbox` | `com.apple.security.app-sandbox` and names starting with `com.apple.security.temporary-exception.` |
| `network` | Names starting with `com.apple.security.network.` |
| `keychain` | `keychain-access-groups` and `com.apple.security.smartcard` |
| `icloud` | Names starting with `com.apple.developer.icloud-`, `com.apple.developer.ubiquity-`, or `com.apple.developer.cloudkit` |
| `other` | Every remaining name |

Some classifications may be surprising. The collector puts the VPN and Network
Extension entitlement names listed above in `privilege`. It puts
`com.apple.security.cs.allow-jit` in `other`. These are Rootstock's current
rules, not an Apple-defined taxonomy.

The collector marks `tcc`, `injection`, and `privilege` entries as
`is_security_critical`. It marks names containing `com.apple.private.` as
private. Both flags describe a classification, not a confirmed vulnerability.
The graph's `EntitlementData.category` accepts the same eight values.

## Reading the result

Use a category to decide which evidence to inspect next:

- For `tcc` and `injection`, inspect recorded grants and modeled injection
  relationships together. A rule match alone does not establish inherited
  access or successful injection.
- For `privilege`, check signing identity and the conditions under which the
  capability is available.
- For `sandbox`, review entitlement values and exceptions against the app's
  purpose. The presence of the sandbox key alone does not establish its value.
- For `keychain`, inspect access groups, item access controls, and authentication
  requirements before concluding that an item can be read.
- For `network` and `icloud`, check configuration and runtime state. Declared
  capabilities do not show whether an extension is active or data is syncing.
- Treat `other` as unclassified. It does not mean low risk.

## Relationship to scoring

Entitlement categories are distinct from the graph's `attack_categories`.
[`infer_risk_score.py`](../../graph/src/rootstock_graph/inference/infer_risk_score.py)
scores application conditions such as injection methods, TCC grants, tier,
CVE relationships, certificate issues, and Electron permission inheritance.
It does not assign a weight to each of the eight entitlement categories.

Risk and vulnerability rules use the predicates in
[`category_predicates.py`](../../graph/src/rootstock_graph/category_predicates.py).
Read the supporting relationships and the [severity reference](severity-mapping.md)
alongside a score.
