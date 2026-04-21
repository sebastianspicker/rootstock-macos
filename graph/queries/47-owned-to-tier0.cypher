// Name: Shortest Paths from Owned Nodes to Tier 0 Assets
// Purpose: Find the shortest escalation path from any owned node to any Tier 0 (crown jewel) application
// Category: Red Team
// Severity: Critical
// Parameters: none
// Attack: Prioritized attack path — owned nodes to the most critical assets on the system
// Prerequisites: import.py + infer.py + mark_owned.py + tier_classification.py must have run

MATCH (src)
WHERE src.owned = true
MATCH (target:Application {tier: 0})
WHERE src <> target
MATCH p = shortestPath((src)-[:CAN_INJECT_INTO|CHILD_INHERITS_TCC|CAN_SEND_APPLE_EVENT|HAS_TCC_GRANT|CAN_HIJACK|PERSISTS_VIA|CAN_READ_KEYCHAIN|SHARES_KEYCHAIN_GROUP|COMMUNICATES_WITH|HAS_TRANSITIVE_FDA|SUDO_NOPASSWD|CAN_CHANGE_PASSWORD|CAN_READ_KERBEROS|CAN_WRITE|CAN_MODIFY_TCC|CAN_INJECT_SHELL|ACCESSIBLE_BY|CAN_CONTROL_VIA_A11Y|CAN_BLIND_MONITORING|CAN_DEBUG*..6]->(target))
RETURN p,
       length(p)                                                AS path_length,
       coalesce(src.name, src.bundle_id, '?')                  AS source_name,
       target.name                                              AS target_name,
       target.bundle_id                                         AS target_bundle_id,
       [n IN nodes(p) | coalesce(n.name, n.display_name, n.bundle_id, '?')] AS node_names,
       [r IN relationships(p) | type(r)]                        AS rel_types
ORDER BY path_length ASC, target.name
LIMIT 25
