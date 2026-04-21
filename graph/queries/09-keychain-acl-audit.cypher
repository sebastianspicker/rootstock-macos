// Name: Keychain ACL Audit
// Purpose: Find apps with direct Keychain read access via ACL trusted-app list
// Category: Blue Team
// Severity: High
// Parameters: none
// Prerequisites: import.py must have run
//
// Finds Application nodes that are explicitly listed in a Keychain item's
// ACL trusted-application list — meaning the app can read that credential
// without prompting the user.
//
// High-value finding: an attacker who compromises or injects into an app
// with CAN_READ_KEYCHAIN gains silent access to those stored credentials.
//
// Usage:
//   cypher-shell -u neo4j -p rootstock < graph/queries/09-keychain-acl-audit.cypher
//   Or paste into Neo4j Browser.

MATCH (a:Application)-[:CAN_READ_KEYCHAIN]->(k:Keychain_Item)

// Optionally join injection vulnerability
WITH a, k,
     size(a.injection_methods) > 0 AS app_is_injectable

RETURN
    a.name              AS app_name,
    a.bundle_id         AS bundle_id,
    a.injection_methods AS injection_methods,
    k.label             AS keychain_label,
    k.kind              AS kind,
    k.service           AS service,
    k.access_group      AS access_group,
    app_is_injectable

ORDER BY app_is_injectable DESC, a.name, k.kind, k.label
LIMIT 100
