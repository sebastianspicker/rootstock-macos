// Name: Non-Apple Authorization Plugins
// Purpose: Find third-party SecurityAgent plugins that could intercept authentication
// Category: Blue Team
// Severity: High
// Parameters: none
// Prerequisites: import.py must have run
// ATT&CK: T1556.001

MATCH (ap:AuthorizationPlugin)
WHERE ap.team_id IS NULL OR NOT ap.team_id STARTS WITH 'apple'
RETURN ap.name    AS plugin_name,
       ap.path    AS path,
       ap.team_id AS team_id,
       CASE
         WHEN ap.team_id IS NULL THEN 'Unsigned — Critical'
         ELSE 'Third-party — Review'
       END AS risk_assessment
ORDER BY ap.team_id IS NULL DESC, ap.name ASC
