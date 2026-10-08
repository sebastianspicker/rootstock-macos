// Name: Process to Listener Map
// Purpose: Which running process (and app) owns each listening socket, with the number of endpoints reachable from other machines
// Category: Blue Team
// Severity: Informational
// Parameters: none
// ATT&CK: T1049
// Prerequisites: rootstock-graph-import-scan must have run (collector module networklisteners)

MATCH (p:Process)-[:LISTENS_ON]->(nl:NetworkListener)
OPTIONAL MATCH (p)-[:INSTANCE_OF]->(a:Application)
WITH p, a,
     collect(DISTINCT nl.endpoint) AS endpoints,
     count(DISTINCT CASE WHEN nl.exposed THEN nl END) AS exposed_endpoints,
     count(DISTINCT CASE WHEN nl.reachable_without_firewall THEN nl END) AS unfiltered_endpoints
RETURN p.pid                AS pid,
       p.command            AS command,
       p.user               AS user,
       a.name               AS application,
       p.bundle_id          AS bundle_id,
       endpoints,
       exposed_endpoints,
       unfiltered_endpoints
ORDER BY unfiltered_endpoints DESC, exposed_endpoints DESC, command ASC, pid ASC
