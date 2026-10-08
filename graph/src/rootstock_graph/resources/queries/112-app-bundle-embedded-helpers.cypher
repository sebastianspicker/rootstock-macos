// Name: App-Bundle Embedded Launch Items
// Purpose: Launch agents, daemons and login items shipped inside an application bundle (Contents/Library/LaunchAgents, LaunchDaemons, LoginItems) and the app that contains them
// Category: Forensic
// Severity: Informational
// Parameters: none
// ATT&CK: T1543.001, T1543.004
// Prerequisites: rootstock-graph-import-scan must have run

MATCH (l:LaunchItem)
WHERE l.bundle_path IS NOT NULL
OPTIONAL MATCH (a:Application)-[:PERSISTS_VIA]->(l)
WHERE l.bundle_path = a.path OR l.bundle_path STARTS WITH a.path + '/'
WITH l, collect(DISTINCT a.name) AS applications, collect(DISTINCT a.team_id) AS team_ids
RETURN l.bundle_path        AS bundle_path,
       applications,
       team_ids,
       l.label              AS label,
       l.type               AS type,
       l.program            AS program,
       l.program_team_id    AS program_team_id,
       l.loaded             AS loaded,
       l.disabled           AS disabled,
       l.triggers           AS triggers
ORDER BY bundle_path ASC, type ASC, label ASC
