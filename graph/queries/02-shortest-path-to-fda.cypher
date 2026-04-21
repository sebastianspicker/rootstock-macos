// Name: Shortest Attack Path to Full Disk Access
// Purpose: From the attacker_payload node, find the shortest chain to Full Disk Access
// Category: Red Team
// Severity: Critical
// Parameters: none
// Attack: Multi-hop privilege escalation through injection + TCC inheritance
// Prerequisites: import.py + infer.py must have run
// Note: shortestPath traverses any relationship type. Adjust [*..N] for depth limit.

MATCH (attacker:Application {bundle_id: 'attacker.payload'}),
      (fda:TCC_Permission {service: 'kTCCServiceSystemPolicyAllFiles'})
MATCH p = shortestPath((attacker)-[*..5]->(fda))
RETURN p,
       length(p)                                                AS path_length,
       [n IN nodes(p) | coalesce(n.name, n.display_name, '?')] AS node_names,
       [r IN relationships(p) | type(r)]                        AS rel_types
ORDER BY path_length ASC
LIMIT 10
