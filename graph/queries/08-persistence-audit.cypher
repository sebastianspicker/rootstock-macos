// Name: Persistence Audit — High-Risk Third-Party Persistence
// Purpose: Find third-party LaunchDaemons/Agents running as root or linked to injectable apps
// Category: Blue Team
// Severity: High
// Parameters: none
// Prerequisites: import.py must have run
// ATT&CK: T1546.004, T1547.011
//
// Finds third-party LaunchDaemons and LaunchAgents that:
//   1. Run as root (RUNS_AS root User node, or daemon with no user = root by default)
//   2. Are associated with an injectable Application (missing_library_validation or dyld_insert)
//
// High-value finding: an attacker who injects into a persistence item's parent app
// gains persistent code execution as root.
//
// Usage:
//   cypher-shell -u neo4j -p rootstock < graph/queries/08-persistence-audit.cypher
//   Or paste into Neo4j Browser.

MATCH (l:LaunchItem)
WHERE l.type IN ['daemon', 'agent']
  AND NOT l.label STARTS WITH 'com.apple.'
  AND NOT l.path STARTS WITH '/System/'

// Optionally join RUNS_AS user
OPTIONAL MATCH (l)-[:RUNS_AS]->(u:User)

// Optionally join PERSISTS_VIA from an injectable app
OPTIONAL MATCH (a:Application)-[:PERSISTS_VIA]->(l)

WITH l, u, a,
     // Daemons without explicit user run as root
     CASE
       WHEN u.name = 'root' OR (l.type = 'daemon' AND u IS NULL) THEN true
       ELSE false
     END AS runs_as_root,
     CASE
       WHEN a IS NOT NULL AND size(a.injection_methods) > 0 THEN true
       ELSE false
     END AS app_is_injectable

WHERE runs_as_root = true OR app_is_injectable = true

RETURN
    l.label                     AS label,
    l.type                      AS type,
    l.program                   AS program,
    l.run_at_load               AS run_at_load,
    COALESCE(u.name, 'root')    AS runs_as,
    a.name                      AS app_name,
    a.bundle_id                 AS bundle_id,
    a.injection_methods         AS injection_methods,
    runs_as_root,
    app_is_injectable
ORDER BY runs_as_root DESC, app_is_injectable DESC, l.label
LIMIT 50
