// Name: Persistent Root Code Execution via Injectable Apps
// Purpose: Injectable apps whose LaunchDaemons run as root — injection = persistent root exec
// Category: Red Team
// Severity: Critical
// Parameters: none
// Prerequisites: import.py + infer.py must have run; Phase 3.2 (Persistence) data required
//
// Attack: Inject parent app → app controls root LaunchDaemon → persistent root code execution
//
// An attacker who injects a process that persists via a root-level LaunchDaemon gains
// persistence across reboots and code execution as root — the most severe possible escalation.

MATCH (app:Application)-[:PERSISTS_VIA]->(l:LaunchItem)
MATCH (:Application {bundle_id: 'attacker.payload'})-[inj:CAN_INJECT_INTO]->(app)

// Determine if the LaunchItem runs as root
OPTIONAL MATCH (l)-[:RUNS_AS]->(u:User)
WITH app, l, u, collect(DISTINCT inj.method) AS injection_methods,
     CASE
       WHEN u.name = 'root' OR (l.type = 'daemon' AND u IS NULL) THEN true
       ELSE false
     END AS runs_as_root

// Also fetch any TCC grants (compounding the severity)
OPTIONAL MATCH (app)-[:HAS_TCC_GRANT {allowed: true}]->(perm:TCC_Permission)
WITH app, l, u, injection_methods, runs_as_root, collect(DISTINCT perm.display_name) AS tcc_grants

RETURN app.name                 AS app_name,
       app.bundle_id            AS bundle_id,
       l.label                  AS launch_item,
       l.type                   AS item_type,
       l.program                AS program,
       l.run_at_load            AS run_at_load,
       coalesce(u.name, 'root') AS runs_as,
       runs_as_root,
       injection_methods,
       tcc_grants,
       size(injection_methods)  AS method_count
ORDER BY runs_as_root DESC, method_count DESC, app.name
LIMIT 50
