// Name: XPC Services Without Client Verification
// Purpose: Find XPC services that lack SMAuthorizedClients — any process can connect
// Category: Red Team
// Severity: High
// Parameters: none
// Attack: Connect to unprotected XPC service from attacker process → invoke privileged operations
// CVE: CVE-2024-40781
// ATT&CK: T1559.001
// Prerequisites: import.py must have run

MATCH (x:XPC_Service)
WHERE coalesce(x.has_client_verification, false) = false
  AND size(x.mach_services) > 0
OPTIONAL MATCH (a:Application)-[:COMMUNICATES_WITH]->(x)
RETURN x.label                     AS xpc_label,
       x.program                   AS program,
       x.type                      AS service_type,
       x.user                      AS runs_as,
       x.mach_services             AS mach_services,
       collect(DISTINCT a.name)    AS connected_apps,
       size(x.entitlements)        AS entitlement_count
ORDER BY x.type DESC, x.label ASC
