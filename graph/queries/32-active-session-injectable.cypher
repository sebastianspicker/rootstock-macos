// Name: Active Sessions on Injectable Apps
// Purpose: Find users with active login sessions who have injectable apps with TCC grants
// Category: Red Team
// Severity: High
// Parameters: none
// Attack: Hijack active session context → inject into user's apps → inherit TCC grants
// Prerequisites: import.py + infer.py must have run
// CVE: CVE-2025-24085
// ATT&CK: T1574.006

MATCH (u:User)-[:HAS_SESSION]->(s:LoginSession)
MATCH (:Application {bundle_id: 'attacker.payload'})-[inj:CAN_INJECT_INTO]->(app:Application)
MATCH (app)-[:HAS_TCC_GRANT {allowed: true}]->(t:TCC_Permission)
// Join user to app: the user must run this app (via launch item)
MATCH (app)-[:PERSISTS_VIA]->(li:LaunchItem)-[:RUNS_AS]->(u)
RETURN u.name                           AS username,
       s.terminal                       AS terminal,
       s.session_type                   AS session_type,
       s.login_time                     AS login_time,
       app.name                         AS injectable_app,
       app.bundle_id                    AS bundle_id,
       collect(DISTINCT inj.method)     AS injection_methods,
       collect(DISTINCT t.service)      AS tcc_permissions,
       collect(DISTINCT li.label)       AS user_launch_items
ORDER BY size(tcc_permissions) DESC, u.name ASC
