// Name: Full Attack Surface Map
// Purpose: Return every inferred attack edge — the complete enumeration of attack paths
// Category: Forensic
// Severity: Informational
// Parameters: none
// Prerequisites: import.py + infer.py must have run
//
// Use case: Machine-readable export of the full attack surface for integration
// with external tools, dashboards, or ticketing systems. Each row is one
// potential attack vector that needs to be triaged or remediated.
//
// Edge types included:
//   CAN_INJECT_INTO      — code injection opportunities
//   CHILD_INHERITS_TCC   — Electron TCC inheritance
//   CAN_SEND_APPLE_EVENT — Apple Event automation abuse

MATCH (attacker:Application {bundle_id: 'attacker.payload'})-[r:CAN_INJECT_INTO]->(target:Application)
OPTIONAL MATCH (target)-[:HAS_TCC_GRANT {allowed: true}]->(perm:TCC_Permission)
WITH 'CAN_INJECT_INTO' AS attack_type,
     target.name                              AS target_app,
     target.bundle_id                         AS target_bundle_id,
     target.path                              AS target_path,
     target.team_id                           AS team_id,
     r.method                                 AS method,
     collect(DISTINCT perm.display_name)      AS permissions_gained,
     collect(DISTINCT perm.service)           AS permission_services

RETURN attack_type,
       target_app,
       target_bundle_id,
       target_path,
       team_id,
       method,
       permissions_gained,
       permission_services,
       size(permissions_gained) AS permission_count

UNION ALL

MATCH (attacker2:Application {bundle_id: 'attacker.payload'})-[r:CHILD_INHERITS_TCC]->(app:Application {is_electron: true})
OPTIONAL MATCH (app)-[:HAS_TCC_GRANT {allowed: true}]->(perm:TCC_Permission)
WITH 'CHILD_INHERITS_TCC' AS attack_type,
     app.name                                 AS target_app,
     app.bundle_id                            AS target_bundle_id,
     app.path                                 AS target_path,
     app.team_id                              AS team_id,
     'electron_env_var'                       AS method,
     collect(DISTINCT perm.display_name)      AS permissions_gained,
     collect(DISTINCT perm.service)           AS permission_services
RETURN attack_type, target_app, target_bundle_id, target_path, team_id, method,
       permissions_gained, permission_services, size(permissions_gained) AS permission_count

UNION ALL

MATCH (source:Application)-[r:CAN_SEND_APPLE_EVENT]->(target:Application)
      -[:HAS_TCC_GRANT {allowed: true}]->(perm:TCC_Permission)
WHERE NOT (source)-[:HAS_TCC_GRANT {allowed: true}]->(perm)
  AND source.bundle_id <> 'attacker.payload'
WITH 'CAN_SEND_APPLE_EVENT' AS attack_type,
     source.name                              AS target_app,
     source.bundle_id                         AS target_bundle_id,
     source.path                              AS target_path,
     source.team_id                           AS team_id,
     'apple_event_cascade'                    AS method,
     collect(DISTINCT perm.display_name)      AS permissions_gained,
     collect(DISTINCT perm.service)           AS permission_services
RETURN attack_type, target_app, target_bundle_id, target_path, team_id, method,
       permissions_gained, permission_services, size(permissions_gained) AS permission_count

ORDER BY permission_count DESC, attack_type, target_app
