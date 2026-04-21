// Name: High-EPSS Injectable Applications
// Purpose: Injectable apps with high exploitation probability (EPSS > 0.3) — active threat targets
// Category: Red Team
// Severity: Critical
// Parameters: none
// Prerequisites: import.py + import_vulnerabilities.py + tier_classification.py must have run

MATCH (app:Application)-[:AFFECTED_BY]->(v:Vulnerability)
WHERE v.epss_score > 0.3
  AND size(app.injection_methods) > 0
RETURN app.name AS app_name,
       app.bundle_id AS bundle_id,
       app.injection_methods AS injection_methods,
       v.cve_id AS cve_id,
       v.cvss_score AS cvss,
       v.epss_score AS epss,
       v.epss_percentile AS epss_percentile,
       CASE WHEN v.in_kev THEN 'KEV' ELSE '' END AS kev_status,
       v.title AS cve_title,
       app.tier AS tier
ORDER BY v.epss_score DESC, v.cvss_score DESC
