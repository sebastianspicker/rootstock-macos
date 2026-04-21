// Name: All Inbound Paths to Target Asset
// Purpose: Given a target bundle_id or TCC service, show all inbound paths from owned nodes
// Category: Red Team
// Severity: Critical
// Parameters: $bundle_id (target application bundle_id, e.g. "com.apple.Terminal")
// Attack: Asset-centric analysis — identify all ways an attacker can reach a specific high-value target
// Prerequisites: import.py + infer.py must have run; mark_owned.py to set owned nodes

MATCH (target:Application {bundle_id: $bundle_id})
MATCH (src)
WHERE src.owned = true AND src <> target
MATCH p = shortestPath((src)-[:CAN_INJECT_INTO|CHILD_INHERITS_TCC|CAN_SEND_APPLE_EVENT|HAS_TCC_GRANT|CAN_HIJACK|PERSISTS_VIA|CAN_READ_KEYCHAIN|SHARES_KEYCHAIN_GROUP|COMMUNICATES_WITH|HAS_TRANSITIVE_FDA|SUDO_NOPASSWD|CAN_CHANGE_PASSWORD|CAN_READ_KERBEROS|CAN_WRITE|CAN_MODIFY_TCC|CAN_INJECT_SHELL|ACCESSIBLE_BY|CAN_CONTROL_VIA_A11Y|CAN_BLIND_MONITORING|CAN_DEBUG*..6]->(target))
RETURN p,
       length(p)                                                AS path_length,
       coalesce(src.name, src.bundle_id, '?')                  AS source_name,
       [n IN nodes(p) | coalesce(n.name, n.display_name, n.bundle_id, '?')] AS node_names,
       [r IN relationships(p) | type(r)]                        AS rel_types
ORDER BY path_length ASC
LIMIT 20
