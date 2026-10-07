// Name: Stale TCC Grants (Orphaned Permissions)
// Purpose: TCC grants whose client has no matching Application node in the scan
// Category: Blue Team
// Severity: High
// Parameters: none
// Prerequisites: rootstock-graph-import-scan must have run
//
// Use case: TCC.db retains grant entries when an app is uninstalled. If the same
// bundle_id is later re-used by a malicious app (bundle_id squatting), it would
// inherit the original app's TCC grants. These orphaned grants should be cleaned up.
//
// Detection logic: the importer records every grant whose client could not be
// resolved to an Application node of the same scan as an UnresolvedTCCGrant node
// (path-only clients and uninstalled apps both land here). Review each entry
// before revoking: a path client is not necessarily an orphan.

MATCH (u:UnresolvedTCCGrant)
OPTIONAL MATCH (u)-[:REFERENCES_TCC_PERMISSION]->(perm:TCC_Permission)
RETURN u.client                                   AS client,
       u.client_type                              AS client_type,
       u.service                                  AS service,
       coalesce(perm.display_name, u.display_name) AS permission,
       u.scope                                    AS scope,
       u.allowed                                  AS allowed,
       u.auth_reason                              AS reason,
       u.last_modified                            AS last_modified_epoch,
       u.scan_id                                  AS scan_id
ORDER BY u.client, u.service
LIMIT 100
