// Name: Reachable High-Value Assets from Owned Nodes
// Purpose: Show all TCC permissions, keychain items, and XPC services reachable from owned nodes within N hops
// Category: Red Team
// Severity: Critical
// Parameters: none
// Attack: After initial compromise, enumerate everything reachable without further exploitation
// Prerequisites: import.py + infer.py must have run; mark_owned.py to set owned nodes

MATCH (src)
WHERE src.owned = true
MATCH p = (src)-[:CAN_INJECT_INTO|CHILD_INHERITS_TCC|CAN_SEND_APPLE_EVENT|HAS_TCC_GRANT|CAN_HIJACK|PERSISTS_VIA|CAN_READ_KEYCHAIN|SHARES_KEYCHAIN_GROUP|COMMUNICATES_WITH|HAS_TRANSITIVE_FDA|SUDO_NOPASSWD|CAN_CHANGE_PASSWORD|CAN_READ_KERBEROS|CAN_WRITE|CAN_MODIFY_TCC|CAN_INJECT_SHELL|ACCESSIBLE_BY|CAN_CONTROL_VIA_A11Y|CAN_BLIND_MONITORING|CAN_DEBUG*1..4]->(target)
WHERE (target:TCC_Permission OR target:Keychain_Item OR target:XPC_Service)
WITH DISTINCT src, target, min(length(p)) AS min_hops, labels(target)[0] AS target_type
RETURN coalesce(src.name, src.bundle_id, '?')             AS owned_node,
       target_type,
       coalesce(target.display_name, target.name, target.service, target.label, '?') AS target_name,
       min_hops
ORDER BY min_hops ASC, target_type, target_name
