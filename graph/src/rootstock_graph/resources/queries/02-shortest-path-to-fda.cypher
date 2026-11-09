// Name: Shortest Attack Path to Full Disk Access
// Purpose: From the attacker_payload node, find the shortest chain to Full Disk Access
// Category: Red Team
// Severity: Critical
// Parameters: none
// Attack: Multi-hop privilege escalation through injection + TCC inheritance
// Prerequisites: rootstock-graph-import-scan + rootstock-graph-infer must have run
// Note: walks the attack edge types of query 41 and skips denied TCC grants. Adjust *..N for depth limit.

MATCH (attacker:Application {bundle_id: 'attacker.payload'}),
      (fda:TCC_Permission {service: 'kTCCServiceSystemPolicyAllFiles'})
MATCH p = shortestPath((attacker)-[:CAN_INJECT_INTO|CHILD_INHERITS_TCC|CAN_SEND_APPLE_EVENT|HAS_TCC_GRANT|CAN_HIJACK|PERSISTS_VIA|CAN_READ_KEYCHAIN|SHARES_KEYCHAIN_GROUP|COMMUNICATES_WITH|HAS_TRANSITIVE_FDA|SUDO_NOPASSWD|CAN_CHANGE_PASSWORD|CAN_READ_KERBEROS|CAN_WRITE|CAN_MODIFY_TCC|CAN_INJECT_SHELL|ACCESSIBLE_BY|CAN_CONTROL_VIA_A11Y|CAN_BLIND_MONITORING|CAN_DEBUG*..5]->(fda))
WHERE all(r IN relationships(p) WHERE type(r) <> 'HAS_TCC_GRANT' OR r.allowed)
RETURN p,
       length(p)                                                AS path_length,
       [n IN nodes(p) | coalesce(n.name, n.display_name, '?')] AS node_names,
       [r IN relationships(p) | type(r)]                        AS rel_types
ORDER BY path_length ASC
LIMIT 10
