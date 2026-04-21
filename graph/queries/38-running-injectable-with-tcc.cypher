// Name: Running Injectable Apps with TCC Grants
// Purpose: Find currently running apps that are injectable and have valuable TCC permissions
// Category: Red Team
// Severity: Critical
// Parameters: none
// Attack: Inject into running app → immediately inherit active TCC grants
// Prerequisites: import.py + infer.py must have run
// CVE: CVE-2025-24085, CVE-2025-24201
// ATT&CK: T1574.006

MATCH (:Application {bundle_id: 'attacker.payload'})-[inj:CAN_INJECT_INTO]->(app:Application)
WHERE app.is_running = true
MATCH (app)-[:HAS_TCC_GRANT {allowed: true}]->(t:TCC_Permission)
WITH app, collect(DISTINCT inj.method) AS injection_methods,
     collect(DISTINCT t.service) AS tcc_permissions
RETURN app.name                         AS app_name,
       app.bundle_id                    AS bundle_id,
       app.path                         AS path,
       injection_methods,
       tcc_permissions,
       size(tcc_permissions)            AS permission_count
ORDER BY permission_count DESC, app.name ASC
