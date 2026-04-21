// Name: Tier 0 Inbound Control Audit
// Purpose: For every Tier 0 asset, enumerate all inbound attack paths from owned or injectable sources
// Category: Blue Team
// Severity: Critical
// Parameters: none
// Prerequisites: import.py + infer.py + tier_classification.py must have run
// Forensic: Systematic "who can reach my crown jewels?" — the key blue team posture question

MATCH (target:Application {tier: 0})
OPTIONAL MATCH p = (src)-[:CAN_INJECT_INTO|CHILD_INHERITS_TCC|CAN_SEND_APPLE_EVENT|HAS_TCC_GRANT|CAN_HIJACK|PERSISTS_VIA|CAN_READ_KEYCHAIN|SHARES_KEYCHAIN_GROUP|COMMUNICATES_WITH|HAS_TRANSITIVE_FDA|SUDO_NOPASSWD|CAN_CHANGE_PASSWORD|CAN_READ_KERBEROS|CAN_WRITE|CAN_MODIFY_TCC|CAN_INJECT_SHELL|ACCESSIBLE_BY|CAN_CONTROL_VIA_A11Y|CAN_BLIND_MONITORING|CAN_DEBUG*1..4]->(target)
WHERE src <> target
  AND (src.owned = true OR coalesce(size(src.injection_methods), 0) > 0)
WITH target,
     count(DISTINCT p) AS path_count,
     collect(DISTINCT coalesce(src.name, src.bundle_id, '?'))[..10] AS sample_sources,
     collect(DISTINCT labels(src)[0])[..5] AS source_types
RETURN target.name                         AS tier0_asset,
       target.bundle_id                    AS bundle_id,
       path_count                          AS inbound_paths,
       sample_sources                      AS top_sources,
       source_types                        AS source_node_types
ORDER BY path_count DESC, target.name
