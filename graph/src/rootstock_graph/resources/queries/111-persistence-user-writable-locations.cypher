// Name: Persistence from User-Writable or Temporary Locations
// Purpose: Launch items whose program lives in /tmp, /Users/Shared or a user's home (outside ~/Applications), or whose program or plist a non-root user can write
// Category: Red Team
// Severity: Critical
// Parameters: none
// Attack: Replace the program (or edit the plist) as an ordinary user; launchd runs the replacement at the next start, as root for daemons
// ATT&CK: T1543.004, T1574
// Prerequisites: rootstock-graph-import-scan must have run

MATCH (l:LaunchItem)
WHERE l.program_in_user_writable_location = true
   OR l.program_writable_by_non_root = true
   OR l.plist_writable_by_non_root = true
OPTIONAL MATCH (a:Application)-[:PERSISTS_VIA]->(l)
OPTIONAL MATCH (l)-[:RUNS_AS]->(u:User)
WITH l, collect(DISTINCT a.name) AS applications, head(collect(DISTINCT u.name)) AS user_name
RETURN l.label                               AS label,
       l.type                                AS type,
       l.path                                AS plist_path,
       l.program                             AS program,
       l.program_in_user_writable_location   AS program_in_user_writable_location,
       l.program_writable_by_non_root        AS program_writable_by_non_root,
       l.plist_writable_by_non_root          AS plist_writable_by_non_root,
       l.program_owner                       AS program_owner,
       coalesce(user_name, CASE WHEN l.type = 'daemon' THEN 'root' END) AS runs_as,
       applications
ORDER BY CASE WHEN runs_as = 'root' THEN 0 ELSE 1 END, type ASC, label ASC
