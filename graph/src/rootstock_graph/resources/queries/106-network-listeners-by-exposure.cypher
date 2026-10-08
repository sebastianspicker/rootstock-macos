// Name: Network Listeners by Exposure
// Purpose: Every TCP/UDP listener with its process, owning app, port and firewall state; listeners reachable from other machines without a firewall first
// Category: Blue Team
// Severity: High
// Parameters: none
// ATT&CK: T1210
// Prerequisites: rootstock-graph-import-scan must have run (collector module networklisteners)

MATCH (nl:NetworkListener)
OPTIONAL MATCH (c:Computer {scan_id: nl.scan_id})
OPTIONAL MATCH (p:Process)-[:LISTENS_ON]->(nl)
OPTIONAL MATCH (a:Application)-[:LISTENS_ON]->(nl)
WITH nl, c,
     head(collect(DISTINCT p.command)) AS process_command,
     collect(DISTINCT a.name) AS applications
RETURN c.hostname                     AS hostname,
       nl.protocol                    AS protocol,
       nl.address                     AS address,
       nl.port                        AS port,
       nl.state                       AS state,
       nl.exposed                     AS exposed,
       nl.firewall_enabled            AS firewall_enabled,
       coalesce(nl.reachable_without_firewall, false) AS reachable_without_firewall,
       nl.pid                         AS pid,
       coalesce(process_command, nl.process_name) AS process,
       nl.user                        AS user,
       applications,
       nl.bundle_id                   AS bundle_id
ORDER BY reachable_without_firewall DESC, exposed DESC, port ASC, protocol ASC, pid ASC
