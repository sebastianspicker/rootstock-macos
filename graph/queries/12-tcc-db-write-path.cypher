// Name: TCC Database Write Path (Complete TCC Takeover)
// Purpose: Find apps with Full Disk Access that are injectable — granting write access to TCC.db
// Category: Red Team
// Severity: Critical
// Parameters: none
// Prerequisites: import.py + infer.py must have run
//
// Attack: Inject injectable FDA app → write /Library/Application Support/com.apple.TCC/TCC.db
//         → grant arbitrary TCC permissions to any app → full TCC takeover
//
// Note: Full Disk Access includes write access to TCC.db when SIP is disabled or
// when the process is running as root. This query identifies the highest-value targets.

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
