// Name: Injectable Endpoint Security Framework Clients
// Purpose: Find injectable apps with ESF entitlement that could blind security monitoring
// Category: Red Team
// Severity: Critical
// Parameters: none
// Prerequisites: import.py + infer.py must have run
// Attack: Injectable ESF clients can suppress or manipulate security events, blinding EDR solutions
// CVE: CVE-2024-27842, CVE-2023-41990
// ATT&CK: T1014, T1562.001

MATCH (a:Application)-[:CAN_BLIND_MONITORING]->(se:SystemExtension)
RETURN a.name                  AS esf_app,
       a.bundle_id             AS bundle_id,
       a.injection_methods     AS injection_methods,
       se.identifier           AS extension_id,
       se.team_id              AS extension_team_id,
       a.is_sip_protected      AS sip_protected,
       a.hardened_runtime       AS hardened_runtime
ORDER BY size(a.injection_methods) DESC, a.name
