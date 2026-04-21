// Name: Weak Authorization Rights
// Purpose: Find authorization database rights with weakened security settings
// Category: Blue Team
// Severity: High
// Parameters: none
// Prerequisites: import.py must have run
// ATT&CK: T1548.003

MATCH (ar:AuthorizationRight)
WHERE ar.allow_root = true
   OR ar.require_authentication = false
RETURN ar.name                    AS right_name,
       ar.rule                    AS rule,
       ar.allow_root              AS allow_root,
       ar.require_authentication  AS requires_auth,
       CASE
         WHEN ar.allow_root = true AND ar.require_authentication = false
           THEN 'Critical: no auth required + root bypass'
         WHEN ar.allow_root = true
           THEN 'High: root can bypass authentication'
         WHEN ar.require_authentication = false
           THEN 'High: no authentication required'
       END AS risk_assessment
ORDER BY ar.require_authentication ASC, ar.allow_root DESC, ar.name ASC
