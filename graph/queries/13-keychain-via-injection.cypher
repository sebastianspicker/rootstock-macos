// Name: Keychain Credential Access via Injection
// Purpose: Find injectable apps that have silent Keychain read access (no user prompt)
// Category: Red Team
// Severity: Critical
// Parameters: none
// Prerequisites: import.py + infer.py must have run; Phase 3.3 (Keychain) data required
//
// Attack: Inject app → inherit ACL-trusted access → read credentials silently
//
// CAN_READ_KEYCHAIN edges indicate an app is in the ACL trusted-application list
// for a Keychain item. Apps in this list can read the item without user prompting.
// If such an app is injectable, an attacker inherits this silent access.

MATCH (app:Application)-[:CAN_READ_KEYCHAIN]->(k:Keychain_Item)
MATCH (:Application {bundle_id: 'attacker.payload'})-[inj:CAN_INJECT_INTO]->(app)
WITH app, k, collect(DISTINCT inj.method) AS injection_methods

// Also capture any TCC grants the app holds (bonus attack value)
OPTIONAL MATCH (app)-[:HAS_TCC_GRANT {allowed: true}]->(perm:TCC_Permission)
WITH app, k, injection_methods, collect(DISTINCT perm.display_name) AS tcc_permissions

RETURN app.name                AS app_name,
       app.bundle_id           AS bundle_id,
       app.team_id             AS team_id,
       k.label                 AS keychain_item,
       k.kind                  AS item_kind,
       k.service               AS item_service,
       k.access_group          AS access_group,
       injection_methods,
       tcc_permissions,
       size(injection_methods) AS method_count
ORDER BY method_count DESC, app.name, k.label
LIMIT 50
