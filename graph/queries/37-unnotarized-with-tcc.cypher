// Name: Unnotarized Apps with TCC Grants
// Purpose: Find apps that aren't notarized by Apple but have TCC privacy grants
// Category: Blue Team
// Severity: High
// Parameters: none
// Prerequisites: import.py must have run
// CVE: CVE-2022-42821, CVE-2024-44175
// ATT&CK: T1553.001

MATCH (a:Application)-[:HAS_TCC_GRANT {allowed: true}]->(t:TCC_Permission)
WHERE a.is_notarized = false
  AND a.is_system = false
WITH a, collect(DISTINCT t.service) AS tcc_permissions
RETURN a.name                       AS app_name,
       a.bundle_id                  AS bundle_id,
       a.path                       AS path,
       a.signed                     AS signed,
       a.team_id                    AS team_id,
       tcc_permissions,
       size(tcc_permissions)        AS permission_count
ORDER BY permission_count DESC, a.name ASC
