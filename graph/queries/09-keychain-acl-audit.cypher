// Name: Keychain ACL Audit
// Purpose: Find apps with direct Keychain read access via ACL trusted-app list
// Category: Blue Team
// Severity: High
// Parameters: none
// Prerequisites: import_scan.py must have run
//
// Finds Application nodes explicitly listed in Keychain ACL metadata.
//
// Validate the live item ACL, process identity, and user interaction behavior
// before concluding that a stored item can be read.
//
// Usage:
//   cypher-shell -u neo4j -p "$NEO4J_PASSWORD" < graph/queries/09-keychain-acl-audit.cypher
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
