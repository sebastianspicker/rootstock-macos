// Name: Ad-Hoc Signed Apps with TCC Grants
// Purpose: Find apps signed without a real certificate (CS_ADHOC) that hold TCC permissions
// Category: Red Team
// Severity: Critical
// Parameters: none
// Prerequisites: import.py must have run
// CVE: CVE-2022-42821
// ATT&CK: T1553.001

MATCH (a:Application)-[:HAS_TCC_GRANT {allowed: true}]->(t:TCC_Permission)
WHERE a.is_adhoc_signed = true
  AND a.is_sip_protected = false
WITH a, collect(DISTINCT t.service) AS tcc_grants
RETURN a.name                       AS app_name,
       a.bundle_id                  AS bundle_id,
       a.path                       AS path,
       tcc_grants
ORDER BY size(tcc_grants) DESC
