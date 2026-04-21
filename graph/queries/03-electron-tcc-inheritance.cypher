// Name: Electron App TCC Permission Inheritance
// Purpose: Map which Electron apps pass TCC permissions to child processes
// Category: Red Team
// Severity: High
// Parameters: none
// Attack: ELECTRON_RUN_AS_NODE env var spawns Node.js child that inherits parent's TCC grants
// CVE: CVE-2023-44402
// ATT&CK: T1574.006, T1059.007
// Prerequisites: import.py must have run

MATCH (app:Application {is_electron: true})-[:HAS_TCC_GRANT {allowed: true}]->(perm:TCC_Permission)
WITH app, collect(DISTINCT perm.display_name) AS inherited_permissions
RETURN app.name              AS app_name,
       app.bundle_id         AS bundle_id,
       app.path              AS path,
       inherited_permissions,
       app.injection_methods AS injection_methods,
       size(inherited_permissions) AS permission_count
ORDER BY permission_count DESC, app.name ASC
