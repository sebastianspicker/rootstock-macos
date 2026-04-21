// Name: Quarantine Bypass Apps with TCC Grants
// Purpose: Find unquarantined apps that hold TCC grants — Gatekeeper bypass with privileged access
// Category: Red Team
// Severity: Critical
// Parameters: none
// Prerequisites: import.py and infer.py must have run
// CVE: CVE-2022-42821, CVE-2024-44175
// ATT&CK: T1553.001

MATCH (a:Application)-[:HAS_TCC_GRANT {allowed: true}]->(t:TCC_Permission)
WHERE coalesce(a.has_quarantine_flag, false) = false
  AND coalesce(a.is_notarized, false) = false
  AND a.is_system = false
  AND NOT coalesce(a.is_sip_protected, false)
WITH a, collect(DISTINCT t.service) AS tcc_permissions
RETURN a.name                       AS app_name,
       a.bundle_id                  AS bundle_id,
       a.path                       AS path,
       a.signed                     AS signed,
       a.team_id                    AS team_id,
       a.injection_methods          AS injection_methods,
       a.quarantine_agent           AS quarantine_agent,
       tcc_permissions,
       size(tcc_permissions)        AS permission_count
ORDER BY permission_count DESC, a.name ASC
