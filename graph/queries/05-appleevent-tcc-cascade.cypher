// Name: Apple Event TCC Permission Cascade
// Purpose: Find apps that gain TCC access transitively via Apple Event automation
// Category: Red Team
// Severity: High
// Parameters: none
// Attack: App A automates App B (via CAN_SEND_APPLE_EVENT) → App A can invoke App B's
//         privileged capabilities, effectively gaining App B's TCC permissions.
// Prerequisites: import.py + infer.py must have run

MATCH (source:Application)-[:CAN_SEND_APPLE_EVENT]->(target:Application)
      -[:HAS_TCC_GRANT {allowed: true}]->(perm:TCC_Permission)
WHERE NOT (source)-[:HAS_TCC_GRANT {allowed: true}]->(perm)
  AND source.bundle_id <> 'attacker.payload'
  AND target.bundle_id <> 'attacker.payload'
RETURN source.name                           AS source_app,
       source.bundle_id                     AS source_bundle_id,
       target.name                          AS target_app,
       perm.display_name                    AS permission_gained,
       perm.service                         AS permission_service,
       size(source.injection_methods) > 0  AS source_is_injectable,
       source.injection_methods             AS source_injection_methods
ORDER BY source.name ASC, perm.display_name ASC
