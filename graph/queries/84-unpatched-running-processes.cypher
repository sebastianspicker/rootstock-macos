// Name: Running Injectable Processes with CVEs
// Purpose: Currently running, injectable processes with known CVE associations — live exploitation targets
// Category: Red Team
// Severity: Critical
// Parameters: none
// Prerequisites: import.py + import_vulnerabilities.py + tier_classification.py must have run

MATCH (app:Application)-[:AFFECTED_BY]->(v:Vulnerability)
WHERE app.is_running = true
  AND size(app.injection_methods) > 0
OPTIONAL MATCH (app)-[:HAS_TCC_GRANT {allowed: true}]->(perm:TCC_Permission)
RETURN app.name AS app_name,
       app.bundle_id AS bundle_id,
       app.injection_methods AS injection_methods,
       collect(DISTINCT perm.service) AS tcc_permissions,
       v.cve_id AS cve_id,
       v.cvss_score AS cvss,
       v.epss_score AS epss,
       CASE WHEN v.in_kev THEN 'KEV' ELSE '' END AS kev_status,
       v.title AS cve_title,
       app.tier AS tier
ORDER BY coalesce(v.epss_score, -1) DESC, v.cvss_score DESC
