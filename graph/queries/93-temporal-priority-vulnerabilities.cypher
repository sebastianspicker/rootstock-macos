// Name: Temporal Priority Vulnerabilities
// Purpose: CVEs ranked by temporal urgency score combining CVSS, EPSS, and age decay
// Category: Blue Team
// Severity: High
// Parameters: none
// Prerequisites: import.py + import_vulnerabilities.py must have run

MATCH (v:Vulnerability)
WHERE v.temporal_priority IS NOT NULL
OPTIONAL MATCH (app:Application)-[:AFFECTED_BY]->(v)
RETURN v.cve_id AS cve_id,
       v.title AS title,
       v.temporal_priority AS temporal_priority,
       v.cvss_score AS cvss,
       v.epss_score AS epss,
       CASE WHEN v.in_kev THEN 'KEV' ELSE '' END AS kev_status,
       v.exploitation_status AS exploitation,
       count(DISTINCT app) AS affected_app_count
ORDER BY v.temporal_priority DESC
