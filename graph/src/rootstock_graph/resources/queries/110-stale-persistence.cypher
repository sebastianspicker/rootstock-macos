// Name: Stale Persistence (Program Missing)
// Purpose: Launch items whose program no longer exists on disk; whoever can create a file at that path gets it run at the next start
// Category: Blue Team
// Severity: Informational
// Parameters: none
// ATT&CK: T1543.004, T1574
// Prerequisites: rootstock-graph-import-scan must have run

MATCH (l:LaunchItem)
WHERE l.program_exists = false
OPTIONAL MATCH (a:Application)-[:PERSISTS_VIA]->(l)
WITH l, collect(DISTINCT a.name) AS applications
RETURN l.label             AS label,
       l.type              AS type,
       l.path              AS plist_path,
       l.program           AS missing_program,
       l.loaded            AS loaded,
       l.disabled          AS disabled,
       l.run_at_load       AS run_at_load,
       l.plist_modified    AS plist_modified,
       applications
ORDER BY CASE type WHEN 'daemon' THEN 0 ELSE 1 END, label ASC
