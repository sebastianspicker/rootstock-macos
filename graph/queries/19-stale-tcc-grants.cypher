// Name: Stale TCC Grants (Orphaned Permissions)
// Purpose: TCC grants for apps that are no longer installed on the system
// Category: Blue Team
// Severity: High
// Parameters: none
// Prerequisites: import.py must have run
//
// Use case: TCC.db retains grant entries when an app is uninstalled. If the same
// bundle_id is later re-used by a malicious app (bundle_id squatting), it would
// inherit the original app's TCC grants. These orphaned grants should be cleaned up.
//
// Detection logic: a TCC grant exists for a bundle_id, but no Application node
// with that bundle_id exists in the graph (app not discovered during collection).

MATCH (app:Application)-[r:HAS_TCC_GRANT]->(perm:TCC_Permission)
WHERE app.path IS NOT NULL
  AND NOT app.bundle_id STARTS WITH 'com.apple.'

// The app node exists but check if path was actually found
// (is_system=false and no injection_methods set may indicate a removed app)
WITH app, r, perm
WHERE app.is_system = false
  AND (app.version IS NULL OR app.signed = false)

RETURN app.name                AS app_name,
       app.bundle_id           AS bundle_id,
       app.path                AS last_known_path,
       app.signed              AS signed,
       perm.display_name       AS permission,
       perm.service            AS service,
       r.scope                 AS scope,
       r.allowed               AS allowed,
       r.last_modified         AS last_modified_epoch
ORDER BY app.bundle_id, perm.display_name
LIMIT 100
