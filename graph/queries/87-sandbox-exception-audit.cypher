// Name: Sandbox Exception Audit
// Purpose: Apps with unconstrained network or file access despite being sandboxed — weakened sandbox posture
// Category: Blue Team
// Severity: High
// Parameters: none
// Attack: Sandboxed apps with broad exceptions may bypass sandbox constraints for file exfiltration or C2
// Prerequisites: import.py must have run
// ATT&CK: T1071, T1005

MATCH (a:Application)-[:HAS_SANDBOX_PROFILE]->(sp:SandboxProfile)
WHERE sp.has_unconstrained_network = true
   OR sp.has_unconstrained_file_read = true
OPTIONAL MATCH (a)-[:HAS_TCC_GRANT {allowed: true}]->(t:TCC_Permission)
WITH a, sp,
     collect(DISTINCT t.display_name) AS tcc_permissions
RETURN a.name                       AS app_name,
       a.bundle_id                  AS bundle_id,
       a.path                       AS path,
       a.is_system                  AS is_system,
       sp.profile_source            AS profile_source,
       sp.has_unconstrained_network AS unconstrained_network,
       sp.has_unconstrained_file_read AS unconstrained_file_read,
       sp.exception_count           AS exception_count,
       sp.file_read_rules           AS file_read_rules,
       sp.file_write_rules          AS file_write_rules,
       sp.network_rules             AS network_rules,
       tcc_permissions,
       size(a.injection_methods) > 0 AS is_injectable
ORDER BY sp.has_unconstrained_file_read DESC,
         sp.has_unconstrained_network DESC,
         sp.exception_count DESC,
         a.name ASC
