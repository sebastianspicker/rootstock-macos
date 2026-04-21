// Name: Injectable Network Extension Apps
// Purpose: Find injectable apps with VPN/content-filter entitlements that could intercept traffic
// Category: Red Team
// Severity: Critical
// Parameters: none
// Prerequisites: import.py must have run
// Attack: Injectable network extension apps can intercept, modify, or redirect all network traffic
// CVE: CVE-2024-27842
// ATT&CK: T1014

MATCH (a:Application)-[:HAS_ENTITLEMENT]->(e:Entitlement)
WHERE e.name IN [
    'com.apple.developer.networking.vpn.api',
    'com.apple.developer.networking.networkextension'
]
AND size(a.injection_methods) > 0
OPTIONAL MATCH (a)-[:HAS_TCC_GRANT {allowed: true}]->(perm:TCC_Permission)
RETURN a.name                              AS app_name,
       a.bundle_id                         AS bundle_id,
       a.injection_methods                 AS injection_methods,
       collect(DISTINCT e.name)            AS network_entitlements,
       collect(DISTINCT perm.display_name) AS tcc_grants,
       a.is_sip_protected                  AS sip_protected,
       a.hardened_runtime                   AS hardened_runtime
ORDER BY size(a.injection_methods) DESC, a.name
