// Name: macOS Release CVEs (NVD)
// Purpose: Published NVD CVEs matching the scanned host's macOS release, with KEV and CVSS leaders
// Category: Blue Team
// Severity: High
// Parameters: none
// Prerequisites: rootstock-graph-cve-enrichment --fetch --scan-json + rootstock-graph-import-vulnerabilities --scan-json must have run

MATCH (c:Computer)-[r:AFFECTED_BY {match_tier: 'cpe'}]->(v:Vulnerability)
WITH c, r.cpe AS cpe, v
ORDER BY coalesce(v.in_kev, false) DESC, coalesce(v.cvss_score, -1) DESC, v.published DESC
WITH c, collect(DISTINCT cpe) AS cpes, collect(DISTINCT v) AS cves
RETURN c.hostname AS hostname,
       c.macos_version AS macos_version,
       cpes AS cpe,
       size(cves) AS cve_count,
       size([cve IN cves WHERE coalesce(cve.in_kev, false)]) AS kev_count,
       reduce(best = 0.0, cve IN cves | CASE WHEN coalesce(cve.cvss_score, 0.0) > best THEN cve.cvss_score ELSE best END) AS max_cvss,
       [cve IN cves | cve.cve_id + CASE WHEN coalesce(cve.in_kev, false) THEN ' (KEV)' ELSE '' END
                      + ' CVSS ' + coalesce(toString(cve.cvss_score), '-')][..10] AS top_cves
ORDER BY kev_count DESC, cve_count DESC, hostname
