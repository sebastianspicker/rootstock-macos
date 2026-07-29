// Name: XPC Services Without SMAuthorizedClients Metadata
// Purpose: Find XPC services requiring review of client authorization controls
// Category: Red Team
// Severity: High
// Parameters: none
// Review service-side audit-token, entitlement, code-signing, and sandbox checks.
// CVE: CVE-2024-40781
// ATT&CK: T1559.001
// Prerequisites: import_scan.py must have run

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
