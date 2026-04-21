// Name: Version-Matched Vulnerabilities
// Purpose: List applications with version-confirmed CVE matches (precise tier)
// Category: Blue Team
// Severity: Critical
// Parameters: none
// Prerequisites: import.py + import_vulnerabilities.py must have run

MATCH (app:Application)-[r:AFFECTED_BY {match_tier: 'precise'}]->(v:Vulnerability)
OPTIONAL MATCH (v)-[:MAPS_TO_TECHNIQUE]->(t:AttackTechnique)
RETURN app.name AS app_name,
       app.bundle_id AS bundle_id,
       app.version AS app_version,
       v.cve_id AS cve_id,
       v.cvss_score AS cvss,
       v.epss_score AS epss,
       CASE WHEN v.in_kev THEN 'KEV' ELSE '' END AS kev_status,
       v.exploitation_status AS exploitation,
       v.title AS cve_title,
       v.affected_versions AS affected_versions,
       v.patched_version AS patched_version,
       collect(DISTINCT t.technique_id) AS attack_techniques
ORDER BY coalesce(v.epss_score, -1) DESC, v.cvss_score DESC
