// Name: TCC Database Write Preconditions
// Purpose: Find FDA and injection relationships that warrant TCC database validation
// Category: Red Team
// Severity: Critical
// Parameters: none
// Prerequisites: import_scan.py + infer.py must have run
//
// Attack model: injection relationship → FDA app → TCC database candidate
//
// A result does not establish write access. Validate SIP, process identity,
// authorization, database location, and current macOS behavior.

MATCH (app:Application)
      -[:HAS_TCC_GRANT {allowed: true}]->
      (:TCC_Permission {service: 'kTCCServiceSystemPolicyAllFiles'})
MATCH (:Application {bundle_id: 'attacker.payload'})-[inj:CAN_INJECT_INTO]->(app)
WITH app, collect(DISTINCT inj.method) AS injection_methods

// Check for additional high-value entitlements that amplify the attack
OPTIONAL MATCH (app)-[:HAS_ENTITLEMENT]->(ent:Entitlement)
WHERE ent.name CONTAINS 'tcc' OR ent.name CONTAINS 'root' OR ent.name CONTAINS 'admin'
WITH app, injection_methods, collect(DISTINCT ent.name) AS relevant_entitlements

RETURN app.name                AS app_name,
       app.bundle_id           AS bundle_id,
       app.path                AS path,
       app.team_id             AS team_id,
       app.is_system           AS is_system,
       injection_methods,
       relevant_entitlements,
       size(injection_methods) AS method_count
ORDER BY method_count DESC, size(relevant_entitlements) DESC, app.name
