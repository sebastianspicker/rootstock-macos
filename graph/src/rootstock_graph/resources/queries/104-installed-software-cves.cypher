// Name: Installed Software CVEs (NVD)
// Purpose: Per installed app, the NVD CVEs matching its exact version via CPE: count, KEV count, highest CVSS, top CVEs
// Category: Blue Team
// Severity: High
// Parameters: none
// Prerequisites: rootstock-graph-cve-enrichment --fetch --scan-json + rootstock-graph-import-vulnerabilities --scan-json must have run

MATCH (app:Application)-[r:AFFECTED_BY {match_tier: 'cpe'}]->(v:Vulnerability)
WITH app, r.cpe AS cpe, v
ORDER BY coalesce(v.in_kev, false) DESC, coalesce(v.cvss_score, -1) DESC, v.published DESC
WITH app, collect(DISTINCT cpe) AS cpes, collect(DISTINCT v) AS cves
RETURN app.name AS app_name,
       app.bundle_id AS bundle_id,
       app.version AS app_version,
       cpes AS cpe,
       size(cves) AS cve_count,
       size([cve IN cves WHERE coalesce(cve.in_kev, false)]) AS kev_count,
       reduce(best = 0.0, cve IN cves | CASE WHEN coalesce(cve.cvss_score, 0.0) > best THEN cve.cvss_score ELSE best END) AS max_cvss,
       [cve IN cves | cve.cve_id][..5] AS top_cves
ORDER BY kev_count DESC, max_cvss DESC, cve_count DESC, app_name
