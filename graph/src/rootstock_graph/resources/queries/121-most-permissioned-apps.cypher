// Name: Most-Permissioned Apps (Blue Team)
// Purpose: Apps with the most allowed TCC grants (potential over-privileging)
// Category: Blue Team
// Severity: Informational
// Parameters: none
// Use case: Find over-privileged apps; split from 07, whose later sections never ran
// Prerequisites: rootstock-graph-import-scan must have run

MATCH (app:Application)-[r:HAS_TCC_GRANT {allowed: true}]->(perm:TCC_Permission)
WITH app, collect(DISTINCT perm.display_name) AS permissions
RETURN app.name            AS app_name,
       app.bundle_id       AS bundle_id,
       app.is_system       AS is_system,
       permissions,
       size(permissions)   AS permission_count
ORDER BY permission_count DESC
LIMIT 20
