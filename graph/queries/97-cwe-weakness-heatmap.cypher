// Name: CWE Weakness Class Heatmap
// Purpose: CWE weakness classes ranked by number of affected applications
// Category: Blue Team
// Severity: High
// Prerequisites: import.py + import_vulnerabilities.py must have run
MATCH (c:CWE)<-[:HAS_CWE]-(v:Vulnerability)<-[:AFFECTED_BY]-(app:Application)
RETURN c.cwe_id AS cwe_id,
       c.name AS weakness_name,
       c.category AS category,
       count(DISTINCT app) AS affected_apps,
       count(DISTINCT v) AS cve_count,
       collect(DISTINCT v.cve_id)[..5] AS sample_cves
ORDER BY affected_apps DESC;
