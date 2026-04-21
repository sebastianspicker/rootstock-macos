// Name: APT Technique Coverage
// Purpose: Which APT techniques are mitigated by existing controls vs exposed
// Category: Blue Team
// Severity: Informational
// Parameters: none
// ATT&CK: T1574.006, T1068, T1059.007
// Prerequisites: import.py + import_vulnerabilities.py must have run

MATCH (g:ThreatGroup)-[:USES_TECHNIQUE]->(t:AttackTechnique)
OPTIONAL MATCH (v:Vulnerability)-[:MAPS_TO_TECHNIQUE]->(t)
OPTIONAL MATCH (app:Application)-[:AFFECTED_BY]->(v)
WITH t,
     collect(DISTINCT g.name) AS used_by_groups,
     collect(DISTINCT v.cve_id) AS related_cves,
     count(DISTINCT app) AS exposed_app_count
RETURN t.technique_id AS technique_id,
       t.name AS technique_name,
       t.tactic AS tactic,
       used_by_groups,
       related_cves,
       exposed_app_count,
       CASE WHEN exposed_app_count = 0 THEN 'Not Exposed' ELSE 'Exposed' END AS status
ORDER BY exposed_app_count DESC, t.technique_id
