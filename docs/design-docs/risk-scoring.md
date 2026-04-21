# Composite Risk Scoring Engine

## Motivation

Rootstock discovers hundreds of security findings per scan. A typical
macOS system may have 50+ applications with injection methods, dozens of
TCC grants, and multiple persistence mechanisms. Without a way to
prioritize, analysts face a wall of findings with no clear starting point.

The risk scoring engine solves this by computing a single 0-10.0 composite
score for every Application node in the graph. The score synthesizes seven
weighted factors that capture the most important dimensions of macOS
application risk: TCC exposure, injection surface, entitlement danger,
CVE presence, running state, sandboxing, and certificate health. The score
is stored directly on the Application node, making it queryable via Cypher
and visible in the interactive graph viewer without recomputing in Python
at report time.

Risk scores also drive two downstream systems: the recommendation engine
(which generates actionable remediation guidance as graph-native nodes)
and the Cypher query library (queries 95-101 operate on risk scores and
recommendations). Together, these systems transform raw graph data into
a prioritized remediation workflow.

## Design Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                      Inference Pipeline                          │
│                                                                  │
│  infer.py orchestrates 17 inference modules in sequence.         │
│  Risk scoring runs LAST, after all other inference + tier         │
│  classification is complete.                                     │
│                                                                  │
│  Step 1: infer_injection.py           CAN_INJECT_INTO            │
│  Step 2: infer_electron.py            CHILD_INHERITS_TCC         │
│  ...                                                             │
│  Step 15: infer_quarantine.py         BYPASSED_GATEKEEPER        │
│  ─────────────────────────────────────────────────────────────── │
│  Step 16: infer_risk_score.py         risk_score, risk_level     │
│  Step 17: infer_recommendations.py    Recommendation nodes       │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│                    Risk Score Computation                         │
│                                                                  │
│  For each Application node:                                      │
│                                                                  │
│  1. ATTACK CATEGORIES — which finding categories apply?          │
│     ┌─ injectable_fda    ┌─ electron_inheritance                 │
│     ├─ dyld_injection    ├─ apple_events                         │
│     ├─ tcc_bypass        ├─ accessibility_abuse                  │
│     ├─ persistence_hijack├─ keychain_access                      │
│     ├─ xpc_exploitation  ├─ esf_bypass                           │
│     ├─ shell_hooks       ├─ sandbox_escape                       │
│     └─ certificate_hygiene                                       │
│                                                                  │
│  2. FINDING COUNTS — critical + high finding tallies             │
│     Critical: injectable_fda, esf_bypass                         │
│     High: dyld_injection, electron_inheritance, apple_events,    │
│           accessibility_abuse, keychain_access, xpc_exploitation │
│                                                                  │
│  3. COMPOSITE SCORE — weighted sum of graph signals              │
│     Injection methods:  3.0                                      │
│     Full Disk Access:   2.0                                      │
│     Any TCC grant:      1.0                                      │
│     Tier 0 (highest):   1.5                                      │
│     CVE exposure:       1.5                                      │
│     Certificate issue:  0.5                                      │
│     Electron inherit:   1.0                                      │
│                         ───                                      │
│     Maximum:           10.5 → clamped to 10.0                    │
│                                                                  │
│  4. RISK LEVEL — classification from score                       │
│     >= 7.0: critical                                             │
│     >= 5.0: high                                                 │
│     >= 3.0: medium                                               │
│     <  3.0: low                                                  │
└──────────────────────────────────────────────────────────────────┘
```

## Implementation Details

### Risk Score Module: infer_risk_score.py

The module runs three server-side Cypher queries in sequence:

**Step 1: Attack Category Detection**

A single query evaluates all 14 category conditions for every Application
node simultaneously. Each condition is expressed as a `CASE WHEN ... THEN
'category_name' ELSE NULL END` expression. The results are collected into
a list, NULL values are filtered out, and the list is stored as the
`attack_categories` property on each Application node.

The category conditions mirror the same Cypher WHERE clauses used in
`import_vulnerabilities._CATEGORY_MATCH` and `report_assembly.py`, ensuring
consistency across the pipeline. Categories include:

- **injectable_fda:** Has FDA TCC grant AND injection methods
- **dyld_injection:** Has injection methods containing 'DYLD'
- **tcc_bypass:** Has any TCC grant
- **electron_inheritance:** Has CHILD_INHERITS_TCC edges
- **persistence_hijack:** Persists via a writable LaunchItem
- **xpc_exploitation:** Communicates with XPC services AND is injectable
- **apple_events:** Has CAN_SEND_APPLE_EVENT edges
- **accessibility_abuse:** Has Accessibility TCC grant AND is injectable
- **keychain_access:** Can read Keychain items AND is injectable
- **esf_bypass:** Has CAN_BLIND_MONITORING edges
- **shell_hooks:** Has CAN_INJECT_SHELL edges
- **sandbox_escape:** Not sandboxed AND is injectable
- **certificate_hygiene:** Signed but certificate is expired, ad-hoc, or
  trust-invalid

**Step 2: Finding Count Computation**

A second query counts the number of critical and high findings per
application by checking category membership:

- **Critical categories:** `injectable_fda`, `esf_bypass`
- **High categories:** `dyld_injection`, `electron_inheritance`,
  `apple_events`, `accessibility_abuse`, `keychain_access`,
  `xpc_exploitation`

These counts are stored as `critical_finding_count` and
`high_finding_count` properties.

**Step 3: Composite Score Computation**

A third query computes the weighted sum for each Application node. The
query uses `OPTIONAL MATCH` patterns to check for graph relationships
(FDA grant, TCC grants, CVE exposure, Electron inheritance) and sums
the weights of all matching conditions:

| Factor | Weight | Detection Method |
|--------|--------|-----------------|
| Injection methods | 3.0 | `size(app.injection_methods) > 0` |
| Full Disk Access | 2.0 | `HAS_TCC_GRANT → TCC_Permission{service: kTCCServiceSystemPolicyAllFiles}` |
| Any TCC grant | 1.0 | `HAS_TCC_GRANT → TCC_Permission` |
| Tier 0 classification | 1.5 | `app.tier = 'T0'` |
| CVE exposure | 1.5 | `AFFECTED_BY → Vulnerability` |
| Certificate issue | 0.5 | `is_certificate_expired OR is_adhoc_signed` |
| Electron inheritance | 1.0 | `CHILD_INHERITS_TCC` edges exist |
| **Maximum** | **10.5** | Clamped to 10.0 |

The raw score is clamped to 10.0 and rounded to two decimal places. The
risk level is derived from the score using fixed thresholds: critical
(>=7.0), high (>=5.0), medium (>=3.0), low (<3.0).

### Weight Rationale

The weights are calibrated to produce meaningful separation between risk
tiers:

- **Injection methods (3.0):** The single most important factor. An
  injectable application is the entry point for nearly every macOS
  privilege escalation. Without injection, most attack paths are
  theoretical. This factor alone puts an application at risk_level
  "medium."

- **Full Disk Access (2.0):** The most sensitive TCC grant. An application
  with FDA can read any file on the system, including other applications'
  TCC databases, Keychain files, and browser data. Combined with injection,
  this scores 5.0 (high) by itself.

- **CVE exposure (1.5):** Known vulnerabilities represent concrete, often
  weaponized attack paths. The weight is slightly lower than injection
  because CVE presence alone (without injection) may not be exploitable
  from the attacker's position.

- **Tier 0 classification (1.5):** Tier 0 applications were classified as
  the highest-priority targets by the tier classification engine (which
  runs before risk scoring). This weight ensures Tier 0 apps receive an
  additional boost.

- **Any TCC grant (1.0):** Moderate weight because TCC grants vary widely
  in sensitivity. Camera access is less impactful than FDA. The specific
  FDA check at 2.0 handles the most dangerous case separately.

- **Electron inheritance (1.0):** Electron apps that inherit TCC grants
  from parent processes are a distinct attack vector. The weight matches
  the general TCC grant weight because the inheritance mechanism adds an
  additional layer of complexity that increases exploitability.

- **Certificate issue (0.5):** Lowest weight because certificate problems
  (expired, ad-hoc signed) are supply chain indicators rather than direct
  attack vectors. They increase risk but are less immediately exploitable
  than injection or CVE exposure.

### Recommendation Engine: infer_recommendations.py

The recommendation engine creates graph-native `Recommendation` nodes
linked to both the applications they apply to and the ATT&CK techniques
they mitigate. This design enables two-directional queries: "what
recommendations apply to this app?" and "which recommendation would
mitigate the most applications?"

Each recommendation has:
- **key:** Unique identifier (e.g., `harden_runtime`)
- **category:** Finding category it addresses (e.g., `injectable_fda`)
- **text:** Human-readable remediation guidance
- **priority:** `critical`, `high`, or `medium`
- **technique_ids:** ATT&CK techniques this mitigates
- **cypher_condition:** Graph pattern that identifies affected applications

The module creates three graph structures:

1. `Recommendation` nodes (MERGE by key) with category, text, priority
2. `MITIGATES` edges from Recommendation to AttackTechnique
3. `HAS_RECOMMENDATION` edges from matching Applications to Recommendation

The 16 built-in recommendations cover:

| Key | Priority | Category |
|-----|----------|----------|
| harden_runtime | critical | injectable_fda |
| library_validation | critical | injectable_fda |
| audit_fda_grants | critical | injectable_fda |
| harden_esf_clients | critical | esf_bypass |
| patch_sandbox_escapes | critical | sandbox_escape |
| disable_electron_node | high | electron_inheritance |
| sandbox_electron | high | electron_inheritance |
| audit_apple_events | high | apple_events |
| require_notarization | high | certificate_hygiene |
| audit_shell_hooks | high | shell_hooks |
| review_mdm_pppc | high | mdm_risk |
| restrict_remote_access | high | lateral_movement |
| audit_file_acls | high | file_acl_escalation |
| monitor_running_injectable | high | running_processes |
| gatekeeper_enforcement | high | gatekeeper_bypass |
| enable_lockdown_mode | medium | physical_security |
| audit_sudoers | medium | authorization_hardening |

### Integration with Cypher Query Library

Seven queries (95-101) operate on risk scores and recommendations:

**Query 95 (High-Risk Applications):** Returns all applications with
`risk_score >= 7.0`, showing their attack categories, finding counts,
tier classification, and TCC grants. This is the primary triage query.

**Query 96 (Risk Score Distribution):** Histogram of risk levels showing
count, average score, min, and max per level. Used for executive reporting
to show the overall security posture.

**Query 97 (CWE Weakness Heatmap):** CWE weakness classes ranked by the
number of affected applications. Shows which vulnerability categories
(memory safety, access control, etc.) dominate the attack surface.

**Query 98 (Memory Safety Risk):** Applications affected by memory safety
CWEs (buffer overflow, use-after-free, out-of-bounds write) that also have
injection paths. These represent the highest-impact exploitation targets.

**Query 99 (ESF Monitoring Gaps):** Critical ESF event types that have
no active SystemExtension monitoring them. Shows blind spots in endpoint
detection.

**Query 100 (Top Recommendations):** Recommendations ranked by the number
of applications they apply to, with mitigated ATT&CK techniques. This
answers "what single remediation action would reduce the most risk?"

**Query 101 (Application Remediation Plan):** All recommendations for a
specific application (parameterized by bundle_id), showing priority,
mitigated techniques, and the application's current risk score. Used to
generate per-application remediation playbooks.

## Graph Model Impact

### Properties Set on Application Nodes

| Property | Type | Set By |
|----------|------|--------|
| `risk_score` | float (0.0-10.0) | infer_risk_score.py |
| `risk_level` | string (critical/high/medium/low) | infer_risk_score.py |
| `attack_categories` | list[string] | infer_risk_score.py |
| `critical_finding_count` | int | infer_risk_score.py |
| `high_finding_count` | int | infer_risk_score.py |

### Node Types Added

| Label | Key Property | Properties |
|-------|-------------|------------|
| `Recommendation` | `key` | category, text, priority |

### Relationships Added

| Relationship | From | To | Meaning |
|-------------|------|-----|---------|
| `HAS_RECOMMENDATION` | Application | Recommendation | Remediation applies |
| `MITIGATES` | Recommendation | AttackTechnique | Remediation mitigates technique |

### Constants (from constants.py)

```python
RISK_SCORE_PROPERTY = "risk_score"
RISK_LEVEL_PROPERTY = "risk_level"
ATTACK_CATEGORIES_PROPERTY = "attack_categories"
CRITICAL_FINDING_COUNT_PROPERTY = "critical_finding_count"
HIGH_FINDING_COUNT_PROPERTY = "high_finding_count"
```

## Trade-offs & Decisions

**Additive scoring model vs. multiplicative.** The scoring uses simple
addition of weights rather than multiplication or more complex formulas.
Additive scoring is transparent and debuggable -- an analyst can look at
an application's score and immediately decompose it into its contributing
factors by checking which conditions are true. Multiplicative scoring
would produce more extreme separation but would be harder to explain and
calibrate.

**Fixed weights vs. configurable.** The weights are hardcoded constants
rather than configurable parameters. This was deliberate: configurable
weights invite bikeshedding and create a false sense of precision. The
weights were calibrated through manual testing against real scan data to
produce reasonable tier separation. If an organization disagrees with the
weighting, they can fork the scoring module or apply their own post-hoc
adjustments via Cypher.

**Score clamped to 10.0, not normalized.** The theoretical maximum (10.5)
is clamped rather than normalized. Normalization (dividing by 10.5) would
compress the scale and reduce the separation between high-scoring
applications. Clamping means that an application hitting all seven factors
scores the same 10.0 as one missing just one 0.5-weight factor, but in
practice this rarely matters because few applications hit all factors
simultaneously.

**Risk level thresholds are symmetric.** The four risk levels are evenly
spaced: 0-3 (low), 3-5 (medium), 5-7 (high), 7-10 (critical). This
was chosen for simplicity. Alternative schemes (e.g., logarithmic
thresholds, percentile-based) were considered but rejected because they
would make the thresholds depend on the population of applications in
the graph, reducing interpretability across scans.

**Recommendations are graph nodes, not report artifacts.** Making
recommendations first-class graph nodes (rather than only including them
in the report output) enables graph-native queries: "which applications
share this recommendation?", "which ATT&CK techniques are unmitigated?",
"what is the coverage of our remediation plan?" This is more expensive
at import time but dramatically more flexible at query time.

**Category conditions are duplicated.** The same Cypher WHERE clauses
appear in `infer_risk_score._CATEGORY_CHECKS`,
`import_vulnerabilities._CATEGORY_MATCH`, and
`report_assembly.py active_categories`. This violates DRY but was
accepted because the three consumers have slightly different requirements:
risk scoring uses them in a CASE expression, vulnerability import uses
them in an UNWIND, and report assembly uses them in individual queries.
Extracting them into a shared function would require a complex abstraction
layer that is harder to debug than straightforward duplication.

## Future Work

- **Weighted TCC scoring.** Replace the binary "any TCC grant" factor
  with a weighted sum of specific TCC services. FDA would contribute
  more than Camera, which would contribute more than Contacts. This
  would improve scoring granularity for applications with many low-value
  TCC grants.

- **Graph-distance scoring.** Incorporate the shortest path distance from
  an attacker entry point to the application. Applications that are
  directly injectable score higher than those reachable only through
  multi-hop transitive paths.

- **Temporal risk decay.** Integrate the CVE temporal_priority score
  into the application risk score. Applications affected by actively
  exploited, high-EPSS CVEs should score higher than those with
  theoretical vulnerabilities.

- **Organization-specific risk policies.** Allow organizations to define
  risk policy overlays (e.g., "applications handling PII receive a +2.0
  bonus") that modify scores based on business context not captured in
  the graph.

- **Risk delta tracking.** Compare risk scores across scans to identify
  applications whose risk is increasing (new TCC grants added, new CVEs
  disclosed, injection methods introduced). Alert on rising risk.

- **Automated remediation ordering.** Use the recommendation graph to
  compute an optimal remediation order that maximizes total risk reduction
  per remediation action, accounting for shared recommendations across
  applications.

- **Custom category definitions.** Allow users to define additional
  attack categories with custom Cypher conditions, extending the scoring
  model without modifying the source code.
