// Name: CISA KEV + Full Disk Access Applications
// Purpose: FDA apps associated with CISA Known Exploited Vulnerabilities — highest-priority remediation targets
// Category: Red Team
// Severity: Critical
// Parameters: none
// Prerequisites: import.py + import_vulnerabilities.py + tier_classification.py must have run

MATCH (app:Application)-[:HAS_TCC_GRANT {allowed: true}]->(:TCC_Permission {service: 'kTCCServiceSystemPolicyAllFiles'})
MATCH (app)-[:AFFECTED_BY]->(v:Vulnerability {in_kev: true})
RETURN app.name AS app_name,
       app.bundle_id AS bundle_id,
       v.cve_id AS cve_id,
       v.cvss_score AS cvss,
       v.epss_score AS epss,
       v.kev_date_added AS kev_added,
       v.kev_ransomware AS ransomware,
       v.title AS cve_title,
       app.injection_methods AS injection_methods,
       app.tier AS tier
ORDER BY coalesce(v.epss_score, -1) DESC, v.cvss_score DESC
