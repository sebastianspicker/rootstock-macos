// Name: Unsandboxed Injectable Apps
// Purpose: Injectable apps that are NOT sandboxed — higher severity injection targets
// Category: Red Team
// Severity: High
// Parameters: none
// Attack: Inject into unsandboxed app → unrestricted file/process/network access
// Prerequisites: import.py + infer.py must have run
// CVE: CVE-2023-32414, CVE-2023-38606
// ATT&CK: T1612

MATCH (:Application {bundle_id: 'attacker.payload'})-[inj:CAN_INJECT_INTO]->(app:Application)
WHERE coalesce(app.is_sandboxed, false) = false
  AND coalesce(inj.sandboxed, false) = false
WITH app, collect(DISTINCT inj.method) AS injection_methods
OPTIONAL MATCH (app)-[:HAS_TCC_GRANT {allowed: true}]->(t:TCC_Permission)
WITH app, injection_methods,
     collect(DISTINCT t.display_name) AS tcc_permissions
RETURN app.name                       AS app_name,
       app.bundle_id                  AS bundle_id,
       app.path                       AS path,
       app.team_id                    AS team_id,
       app.is_sandboxed               AS sandboxed,
       injection_methods,
       tcc_permissions,
       size(tcc_permissions)          AS permission_count,
       size(injection_methods)        AS method_count
ORDER BY permission_count DESC, method_count DESC, app.name ASC
