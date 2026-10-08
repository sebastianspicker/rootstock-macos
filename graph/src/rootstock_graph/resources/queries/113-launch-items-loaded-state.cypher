// Name: Launch Items Loaded vs On Disk
// Purpose: Launch items that are on disk but not loaded by launchd, or disabled in their plist; a job loaded from elsewhere or switched off after install deserves a look
// Category: Forensic
// Severity: Informational
// Parameters: none
// ATT&CK: T1543.001, T1543.004
// Prerequisites: rootstock-graph-import-scan must have run

MATCH (l:LaunchItem)
WHERE l.loaded = false OR l.disabled = true
OPTIONAL MATCH (a:Application)-[:PERSISTS_VIA]->(l)
WITH l, collect(DISTINCT a.name) AS applications
RETURN l.label             AS label,
       l.type              AS type,
       l.path              AS plist_path,
       l.loaded            AS loaded,
       l.disabled          AS disabled,
       CASE
         WHEN l.disabled = true AND l.loaded = true THEN 'disabled in plist but loaded'
         WHEN l.disabled = true THEN 'disabled'
         ELSE 'on disk, not loaded'
       END                 AS state,
       l.run_at_load       AS run_at_load,
       l.program_exists    AS program_exists,
       l.plist_modified    AS plist_modified,
       applications
ORDER BY state ASC, type ASC, label ASC
