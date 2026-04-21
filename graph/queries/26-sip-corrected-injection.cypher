// Name: SIP-Corrected Injection Audit
// Purpose: List apps marked as SIP-protected that would otherwise appear injectable
// Category: Blue Team
// Severity: Informational
// Parameters: none
// Use case: Audit which apps have been excluded from injection analysis by SIP protection
// CVE: CVE-2024-44243, CVE-2024-44294
// ATT&CK: T1562.001
// Prerequisites: import.py must have run

MATCH (app:Application)
WHERE app.is_sip_protected = true
  AND (app.hardened_runtime = false
       OR app.library_validation = false)
RETURN app.name                           AS app_name,
       app.bundle_id                      AS bundle_id,
       app.path                           AS path,
       app.hardened_runtime               AS hardened_runtime,
       app.library_validation             AS library_validation,
       app.is_sip_protected               AS sip_protected
ORDER BY app.name ASC
