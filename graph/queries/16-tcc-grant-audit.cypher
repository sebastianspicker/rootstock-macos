// Name: Full TCC Grant Inventory
// Purpose: Complete audit of all TCC grants — service, app, grant method, age
// Category: Blue Team
// Severity: Informational
// Parameters: $scope (optional: 'user' or 'system', default: all)
// Prerequisites: import.py must have run
//
// Use case: Periodic security audit, baseline establishment, compliance reporting.
// Compare output before/after software installs to detect new TCC grants.

MATCH (app:Application)-[r:HAS_TCC_GRANT]->(perm:TCC_Permission)
WHERE $scope IS NULL OR r.scope = $scope

WITH app, r, perm,
     r.auth_reason AS grant_method,
     CASE WHEN r.allowed = true THEN 'allowed' ELSE 'denied' END AS status

RETURN perm.display_name           AS permission,
       perm.service                AS service,
       app.name                    AS app_name,
       app.bundle_id               AS bundle_id,
       app.is_system               AS is_system_app,
       r.scope                     AS scope,
       status,
       grant_method,
       r.last_modified             AS last_modified_epoch,
       app.team_id                 AS team_id
ORDER BY perm.display_name, status DESC, app.name
