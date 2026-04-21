// Name: Shortest Path from Owned Nodes to Full Disk Access
// Purpose: From any node marked as owned, find the shortest path to FDA — generalizes query 02
// Category: Red Team
// Severity: Critical
// Parameters: none
// Attack: Mark compromised nodes as owned, then discover the shortest escalation path to FDA
// Prerequisites: import.py + infer.py must have run; mark_owned.py to set owned nodes

MATCH (src)
WHERE src.owned = true
MATCH (fda:TCC_Permission {service: 'kTCCServiceSystemPolicyAllFiles'})
MATCH p = shortestPath((src)-[:CAN_INJECT_INTO|CHILD_INHERITS_TCC|CAN_SEND_APPLE_EVENT|HAS_TCC_GRANT|CAN_HIJACK|PERSISTS_VIA|CAN_READ_KEYCHAIN|SHARES_KEYCHAIN_GROUP|COMMUNICATES_WITH|HAS_TRANSITIVE_FDA|SUDO_NOPASSWD|CAN_CHANGE_PASSWORD|CAN_READ_KERBEROS|CAN_WRITE|CAN_MODIFY_TCC|CAN_INJECT_SHELL|ACCESSIBLE_BY|CAN_CONTROL_VIA_A11Y|CAN_BLIND_MONITORING|CAN_DEBUG*..6]->(fda))
RETURN p,
       length(p)                                                AS path_length,
       [n IN nodes(p) | coalesce(n.name, n.display_name, n.bundle_id, '?')] AS node_names,
       [r IN relationships(p) | type(r)]                        AS rel_types,
       src.owned_at                                              AS owned_since
ORDER BY path_length ASC
LIMIT 10
