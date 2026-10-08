// Name: Launchd Environment Injection
// Purpose: Launch items whose plist sets a DYLD_* variable that loads a library (DYLD_INSERT_LIBRARIES, *_PATH), so code enters the program at every start
// Category: Red Team
// Severity: Critical
// Parameters: none
// Attack: A DYLD_INSERT_LIBRARIES entry in a LaunchDaemon/LaunchAgent plist injects code into the job without touching its binary
// ATT&CK: T1574.006, T1543.004
// Prerequisites: rootstock-graph-import-scan must have run

MATCH (l:LaunchItem)
WHERE l.launchd_dyld_injection = true
OPTIONAL MATCH (a:Application)-[:PERSISTS_VIA]->(l)
OPTIONAL MATCH (l)-[:RUNS_AS]->(u:User)
WITH l, collect(DISTINCT a.name) AS applications, head(collect(DISTINCT u.name)) AS user_name
RETURN l.label                       AS label,
       l.type                        AS type,
       l.path                        AS plist_path,
       l.program                     AS program,
       l.dyld_environment            AS dyld_environment,
       l.environment_variable_names  AS environment_variable_names,
       coalesce(user_name, CASE WHEN l.type = 'daemon' THEN 'root' END) AS runs_as,
       l.loaded                      AS loaded,
       l.run_at_load                 AS run_at_load,
       l.plist_writable_by_non_root  AS plist_writable_by_non_root,
       applications
ORDER BY CASE WHEN runs_as = 'root' THEN 0 ELSE 1 END, type ASC, label ASC
