// Name: Owned Node Blast Radius Ranking
// Purpose: Rank each owned node by the count of high-value assets reachable from it
// Category: Red Team
// Severity: Critical
// Parameters: none
// Attack: Prioritize which owned nodes to pivot from by ranking their downstream impact
// Prerequisites: import.py + infer.py must have run; mark_owned.py to set owned nodes

MATCH (src)
WHERE src.owned = true
OPTIONAL MATCH (src)-[:CAN_INJECT_INTO|CHILD_INHERITS_TCC|CAN_SEND_APPLE_EVENT|HAS_TCC_GRANT|CAN_HIJACK|PERSISTS_VIA|CAN_READ_KEYCHAIN|SHARES_KEYCHAIN_GROUP|COMMUNICATES_WITH|HAS_TRANSITIVE_FDA|SUDO_NOPASSWD|CAN_CHANGE_PASSWORD|CAN_READ_KERBEROS|CAN_WRITE|CAN_MODIFY_TCC|CAN_INJECT_SHELL|ACCESSIBLE_BY|CAN_CONTROL_VIA_A11Y|CAN_BLIND_MONITORING|CAN_DEBUG*1..4]->(target)
WHERE (target:TCC_Permission OR target:Keychain_Item OR target:XPC_Service OR target:Application)
  AND target <> src
  AND NOT coalesce(target.owned, false)
WITH src,
     count(DISTINCT target)                                                     AS total_reachable,
     count(DISTINCT CASE WHEN target:TCC_Permission THEN target END)            AS tcc_reachable,
     count(DISTINCT CASE WHEN target:Keychain_Item THEN target END)             AS keychain_reachable,
     count(DISTINCT CASE WHEN target:Application THEN target END)               AS apps_reachable
RETURN coalesce(src.name, src.bundle_id, '?')  AS owned_node,
       labels(src)[0]                           AS node_type,
       src.owned_at                             AS owned_since,
       total_reachable,
       tcc_reachable,
       keychain_reachable,
       apps_reachable
ORDER BY total_reachable DESC
