// Name: Unquarantined Non-System Applications
// Purpose: Find non-system apps missing the com.apple.quarantine xattr — potential Gatekeeper bypass
// Category: Blue Team
// Severity: High
// Parameters: none
// Prerequisites: import.py must have run with quarantine data
// CVE: CVE-2022-42821, CVE-2024-44175
// ATT&CK: T1553.001

MATCH (a:Application)
WHERE coalesce(a.has_quarantine_flag, false) = false
  AND a.is_system = false
  AND NOT coalesce(a.is_sip_protected, false)
OPTIONAL MATCH (a)-[:HAS_TCC_GRANT {allowed: true}]->(t:TCC_Permission)
WITH a, collect(DISTINCT t.service) AS tcc_permissions
RETURN a.name                       AS app_name,
       a.bundle_id                  AS bundle_id,
       a.path                       AS path,
       a.signed                     AS signed,
       a.is_notarized               AS is_notarized,
       a.team_id                    AS team_id,
       a.quarantine_agent           AS quarantine_agent,
       tcc_permissions,
       size(tcc_permissions)        AS permission_count
ORDER BY permission_count DESC, a.name ASC
