// Name: Password Change Attack Paths
// Purpose: Admin users who can change passwords of users owning privileged apps — enables account takeover of TCC-granted applications
// Category: Red Team
// Severity: Critical
// Parameters: none
// Prerequisites: import.py + infer.py must have run

MATCH (attacker:User)-[r:CAN_CHANGE_PASSWORD]->(victim:User)
MATCH (victim_app:Application)-[:PERSISTS_VIA]->(:LaunchItem)-[:RUNS_AS]->(victim)
WHERE EXISTS {
    MATCH (victim_app)-[:HAS_TCC_GRANT {allowed: true}]->(:TCC_Permission)
}
RETURN attacker.name          AS attacker,
       r.reason               AS method,
       victim.name            AS victim_user,
       victim_app.name        AS victim_app,
       victim_app.bundle_id   AS bundle_id,
       collect {
           MATCH (victim_app)-[:HAS_TCC_GRANT {allowed: true}]->(t:TCC_Permission)
           RETURN t.display_name
       }                      AS tcc_grants
ORDER BY attacker.name, victim.name
