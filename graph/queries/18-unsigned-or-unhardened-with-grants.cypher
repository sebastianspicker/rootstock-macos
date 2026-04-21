// Name: Unsigned or Unhardened Apps with TCC Grants
// Purpose: Apps that have TCC grants but lack basic code signing protections
// Category: Blue Team
// Severity: High
// Parameters: none
// Prerequisites: import.py must have run
//
// Use case: Identify immediate risks — apps that hold TCC permissions but have
// no Hardened Runtime or are unsigned. These are trivially injectable and should
// either be remediated or have their TCC grants revoked.
//
// Findings here require no inference engine — the raw data itself shows the risk.

MATCH (app:Application {is_system: false})-[r:HAS_TCC_GRANT {allowed: true}]->(perm:TCC_Permission)
WHERE app.signed = false
   OR app.hardened_runtime = false
   OR app.library_validation = false

WITH app, perm, r,
     CASE WHEN app.signed = false              THEN 'unsigned'
          WHEN app.hardened_runtime = false    THEN 'no_hardened_runtime'
          WHEN app.library_validation = false  THEN 'no_library_validation'
          ELSE 'other'
     END AS risk_reason

WITH app,
     collect(DISTINCT perm.display_name) AS permissions,
     collect(DISTINCT risk_reason) AS risk_reasons

RETURN app.name                    AS app_name,
       app.bundle_id               AS bundle_id,
       app.signed                  AS signed,
       app.hardened_runtime        AS hardened_runtime,
       app.library_validation      AS library_validation,
       app.team_id                 AS team_id,
       permissions,
       size(permissions)           AS permission_count,
       risk_reasons
ORDER BY size(permissions) DESC, app.signed ASC, app.name
LIMIT 50
