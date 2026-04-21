// Name: Over-privileged Applications
// Purpose: Apps with more TCC permissions than typical (> $min_permissions distinct services)
// Category: Blue Team
// Severity: High
// Parameters: $min_permissions (default: 3) — minimum number of TCC services to flag
// Prerequisites: import.py must have run
//
// Use case: Identify applications that have accumulated excessive TCC permissions
// over time. Over-privileged apps violate least-privilege and represent a larger
// blast radius if compromised.

MATCH (app:Application)-[:HAS_TCC_GRANT {allowed: true}]->(perm:TCC_Permission)
WITH app, collect(DISTINCT perm.display_name) AS permissions,
     collect(DISTINCT perm.service) AS services

WHERE size(permissions) > coalesce(toInteger($min_permissions), 3)

// Check injection vulnerability
OPTIONAL MATCH (:Application {bundle_id: 'attacker.payload'})-[inj:CAN_INJECT_INTO]->(app)
WITH app, permissions, services, collect(DISTINCT inj.method) AS injection_methods

RETURN app.name                        AS app_name,
       app.bundle_id                   AS bundle_id,
       app.is_system                   AS is_system,
       app.team_id                     AS team_id,
       permissions,
       size(permissions)               AS permission_count,
       size(injection_methods) > 0     AS is_injectable,
       injection_methods
ORDER BY permission_count DESC, is_injectable DESC, app.name
LIMIT 30
