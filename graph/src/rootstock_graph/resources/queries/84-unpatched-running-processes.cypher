// Name: Running Injectable Processes with CVEs
// Purpose: Currently running, injectable processes with known CVE associations - live exploitation targets
// Category: Red Team
// Severity: Critical
// Parameters: none
// Prerequisites: rootstock-graph-import-scan + rootstock-graph-import-vulnerabilities + rootstock-graph-tier-classification must have run

MATCH (app:Application)-[r:AFFECTED_BY]->(v:Vulnerability)
WHERE r.match_tier IN ['precise', 'cpe']
  AND app.is_running = true
  AND size(app.injection_methods) > 0
OPTIONAL MATCH (app)-[:HAS_TCC_GRANT {allowed: true}]->(perm:TCC_Permission)
RETURN app.name AS app_name,
       app.bundle_id AS bundle_id,
       app.injection_methods AS injection_methods,
       collect(DISTINCT perm.service) AS tcc_permissions,
       r.match_tier AS match_tier,
       coalesce(r.match_source, 'registry') AS match_source,
       r.cpe AS cpe,
       v.source AS cve_source,
       v.cve_id AS cve_id,
       v.cvss_score AS cvss,
       v.epss_score AS epss,
       CASE WHEN v.in_kev THEN 'KEV' ELSE '' END AS kev_status,
       v.title AS cve_title,
       app.tier AS tier
ORDER BY coalesce(v.epss_score, -1) DESC, v.cvss_score DESC
