// Name: APT Group Technique Context
// Purpose: Threat groups whose documented techniques match the exposure classes modeled for apps on this host (context, not confirmed vulnerabilities)
// Category: Red Team
// Severity: Informational
// Parameters: none
// ATT&CK: T1574.006, T1068, T1059.007
// Prerequisites: rootstock-graph-import-scan + rootstock-graph-infer + rootstock-graph-import-vulnerabilities must have run
//
// HAS_CVE_CONTEXT links an app to the reference CVEs of a technique class it is
// exposed to (for example an injectable app to dylib-hijacking CVEs). It does not
// claim the app carries that CVE; version-matched vulnerabilities are AFFECTED_BY
// and appear in queries 80-85.

MATCH (g:ThreatGroup)-[:USES_TECHNIQUE]->(t:AttackTechnique)<-[:MAPS_TO_TECHNIQUE]-(v:Vulnerability)
MATCH (v)<-[link:AFFECTED_BY|HAS_CVE_CONTEXT]-(app:Application)
WITH g, t, v, app, type(link) = 'AFFECTED_BY' AS confirmed
RETURN g.name AS group_name,
       g.group_id AS group_id,
       g.aliases AS aliases,
       collect(DISTINCT t.technique_id) AS techniques,
       collect(DISTINCT v.cve_id) AS reference_cves,
       collect(DISTINCT CASE WHEN confirmed THEN app.name END) AS affected_apps,
       collect(DISTINCT CASE WHEN NOT confirmed THEN app.name END) AS context_apps,
       count(DISTINCT CASE WHEN confirmed THEN app END) AS affected_app_count,
       count(DISTINCT app) AS exposed_app_count
ORDER BY affected_app_count DESC, exposed_app_count DESC, group_name
