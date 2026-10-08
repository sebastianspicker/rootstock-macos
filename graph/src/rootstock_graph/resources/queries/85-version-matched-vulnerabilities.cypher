// Name: Version-Range-Matched Vulnerabilities
// Purpose: List applications with version-range CVE matches (precise registry tier and NVD CPE tier)
// Category: Blue Team
// Severity: Critical
// Parameters: none
// Prerequisites: rootstock-graph-import-scan + rootstock-graph-import-vulnerabilities must have run

MATCH (app:Application)-[r:AFFECTED_BY]->(v:Vulnerability)
WHERE r.match_tier IN ['precise', 'cpe']
OPTIONAL MATCH (v)-[:MAPS_TO_TECHNIQUE]->(t:AttackTechnique)
RETURN app.name AS app_name,
       app.bundle_id AS bundle_id,
       app.version AS app_version,
       r.match_tier AS match_tier,
       coalesce(r.match_source, 'registry') AS match_source,
       r.cpe AS cpe,
       v.source AS cve_source,
       r.matched_criteria AS matched_criteria,
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
