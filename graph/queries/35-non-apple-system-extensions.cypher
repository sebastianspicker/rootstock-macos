// Name: Non-Apple System Extensions
// Purpose: Enumerate third-party system extensions (network filters, endpoint security, drivers)
// Category: Blue Team
// Severity: High
// Parameters: none
// Prerequisites: import.py must have run
// ATT&CK: T1014

MATCH (se:SystemExtension)
RETURN se.identifier      AS identifier,
       se.team_id         AS team_id,
       se.extension_type  AS type,
       se.enabled         AS enabled,
       CASE
         WHEN se.extension_type = 'endpoint_security' THEN 'Endpoint Security Agent — high privilege'
         WHEN se.extension_type = 'network' THEN 'Network Filter — can inspect/modify traffic'
         WHEN se.extension_type = 'driver' THEN 'Driver Extension — kernel-level access'
       END AS risk_note
ORDER BY se.extension_type ASC, se.identifier ASC
