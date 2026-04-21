// Name: APT Group Exposure
// Purpose: APT groups whose techniques map to CVEs affecting applications on this host
// Category: Red Team
// Severity: Critical
// Parameters: none
// ATT&CK: T1574.006, T1068, T1059.007
// Prerequisites: import.py + import_vulnerabilities.py must have run

MATCH (g:ThreatGroup)-[:USES_TECHNIQUE]->(t:AttackTechnique)<-[:MAPS_TO_TECHNIQUE]-(v:Vulnerability)<-[:AFFECTED_BY]-(app:Application)
RETURN g.name AS group_name,
       g.group_id AS group_id,
       g.aliases AS aliases,
       collect(DISTINCT t.technique_id) AS techniques,
       collect(DISTINCT v.cve_id) AS cves,
       collect(DISTINCT app.name) AS affected_apps,
       count(DISTINCT app) AS affected_app_count
ORDER BY affected_app_count DESC, group_name
