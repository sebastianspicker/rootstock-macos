// Name: Expired Signing Certificates with Active TCC Grants
// Purpose: Find apps signed with expired certificates that hold active privacy permissions
// Category: Blue Team
// Severity: High
// Parameters: none
// Prerequisites: import.py must have run
// CVE: CVE-2022-42821
// ATT&CK: T1553.001

MATCH (a:Application)-[:HAS_TCC_GRANT {allowed: true}]->(t:TCC_Permission)
WHERE a.is_certificate_expired = true
  AND a.is_sip_protected = false
WITH a, collect(DISTINCT t.service) AS tcc_grants
RETURN a.name                       AS app_name,
       a.bundle_id                  AS bundle_id,
       a.certificate_expires        AS certificate_expires,
       a.signing_certificate_cn     AS signing_certificate,
       tcc_grants
ORDER BY size(tcc_grants) DESC
