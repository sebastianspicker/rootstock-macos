// Name: Processes Running from User-Writable Locations
// Purpose: Processes whose executable is in a temporary folder, /Users/Shared or a user's Library, Downloads, Desktop or Documents, with the parent that started them
// Category: Blue Team
// Severity: High
// Parameters: none
// ATT&CK: T1036, T1204.002
// Prerequisites: rootstock-graph-import-scan must have run

MATCH (p:Process)
WHERE p.command_in_user_writable_location = true
OPTIONAL MATCH (parent:Process)-[:PARENT_OF]->(p)
OPTIONAL MATCH (p)-[:INSTANCE_OF]->(a:Application)
OPTIONAL MATCH (c:Computer {scan_id: p.scan_id})
RETURN c.hostname          AS hostname,
       p.pid               AS pid,
       p.command           AS command,
       p.user              AS user,
       p.ppid              AS ppid,
       parent.command      AS parent_command,
       parent.user         AS parent_user,
       a.name              AS application,
       p.bundle_id         AS bundle_id,
       EXISTS { MATCH (p)-[:LISTENS_ON]->(:NetworkListener) } AS listens_on_network
ORDER BY listens_on_network DESC, command ASC, pid ASC
