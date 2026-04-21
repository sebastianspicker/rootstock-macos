// Name: CloudKit Container Injection
// Purpose: Apps with CloudKit container entitlements and injection vectors — injectable cloud-connected apps can read/write shared CloudKit data
// Category: Red Team
// Severity: High
// Parameters: none
// Prerequisites: import.py must have run
// CVE: CVE-2023-42926
// ATT&CK: T1537

MATCH (a:Application)-[:HAS_ENTITLEMENT]->(e:Entitlement)
WHERE e.name STARTS WITH 'com.apple.developer.cloudkit'
  AND size(a.injection_methods) > 0
RETURN a.name            AS app,
       a.bundle_id       AS bundle_id,
       a.injection_methods AS injection_methods,
       a.is_sandboxed    AS sandboxed,
       collect(e.name)   AS cloudkit_entitlements
ORDER BY a.name
