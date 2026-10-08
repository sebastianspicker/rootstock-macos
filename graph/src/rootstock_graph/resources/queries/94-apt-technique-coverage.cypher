// Name: APT Technique Coverage
// Purpose: Which threat-group techniques have a modeled exposure on this host (confirmed CVE match or technique context) and which do not
// Category: Blue Team
// Severity: Informational
// Parameters: none
// ATT&CK: T1574.006, T1068, T1059.007
// Prerequisites: rootstock-graph-import-scan + rootstock-graph-infer + rootstock-graph-import-vulnerabilities must have run
//
// "Confirmed" counts apps with a version-matched AFFECTED_BY edge; "Context"
// counts apps that only match the technique's exposure class (HAS_CVE_CONTEXT).

MATCH (g:ThreatGroup)-[:USES_TECHNIQUE]->(t:AttackTechnique)
OPTIONAL MATCH (v:Vulnerability)-[:MAPS_TO_TECHNIQUE]->(t)
OPTIONAL MATCH (app:Application)-[link:AFFECTED_BY|HAS_CVE_CONTEXT]->(v)
WITH t,
     collect(DISTINCT g.name) AS used_by_groups,
     collect(DISTINCT v.cve_id) AS related_cves,
     count(DISTINCT CASE WHEN type(link) = 'AFFECTED_BY' THEN app END) AS affected_app_count,
     count(DISTINCT CASE WHEN type(link) = 'HAS_CVE_CONTEXT' THEN app END) AS context_app_count
RETURN t.technique_id AS technique_id,
       t.name AS technique_name,
       t.tactic AS tactic,
       used_by_groups,
       related_cves,
       affected_app_count,
       context_app_count,
       CASE
         WHEN affected_app_count > 0 THEN 'Confirmed'
         WHEN context_app_count > 0 THEN 'Context'
         ELSE 'Not Exposed'
       END AS status
ORDER BY affected_app_count DESC, context_app_count DESC, t.technique_id
