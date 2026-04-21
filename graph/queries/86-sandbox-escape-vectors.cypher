// Name: Sandbox Escape Vectors via Mach-Lookup
// Purpose: Sandboxed apps with mach-lookup exceptions to privileged XPC services — potential sandbox escape paths
// Category: Red Team
// Severity: Critical
// Parameters: none
// Attack: Inject into sandboxed app → leverage mach-lookup exception → communicate with privileged XPC service → escalate
// Prerequisites: import.py + infer.py must have run
// CVE: CVE-2023-32414, CVE-2023-38606
// ATT&CK: T1559

MATCH (a:Application)-[:HAS_SANDBOX_PROFILE]->(sp:SandboxProfile)
WHERE size(sp.mach_lookup_rules) > 0
  AND size(a.injection_methods) > 0
  AND NOT coalesce(a.is_sip_protected, false)
OPTIONAL MATCH (a)-[:CAN_ACCESS_MACH_SERVICE]->(xpc:XPC_Service)
OPTIONAL MATCH (a)-[:HAS_TCC_GRANT {allowed: true}]->(t:TCC_Permission)
WITH a, sp,
     collect(DISTINCT xpc.label) AS accessible_xpc_services,
     collect(DISTINCT t.display_name) AS tcc_permissions
RETURN a.name                       AS app_name,
       a.bundle_id                  AS bundle_id,
       a.path                       AS path,
       sp.profile_source            AS profile_source,
       sp.mach_lookup_rules         AS mach_lookup_rules,
       accessible_xpc_services,
       a.injection_methods          AS injection_methods,
       tcc_permissions,
       sp.has_unconstrained_network AS unconstrained_network,
       sp.has_unconstrained_file_read AS unconstrained_file_read,
       sp.exception_count           AS exception_count
ORDER BY size(accessible_xpc_services) DESC, sp.exception_count DESC, a.name ASC
