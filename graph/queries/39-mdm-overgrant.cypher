// Name: MDM Overgrant to Scripting Interpreters
// Purpose: Flag MDM profiles that grant sensitive TCC permissions to scripting interpreters
// Category: Blue Team
// Severity: Critical
// Parameters: none
// Prerequisites: import.py + infer.py must have run
// CVE: CVE-2024-44301
// ATT&CK: T1548.004

MATCH (m:MDM_Profile)-[r:MDM_OVERGRANT]->(t:TCC_Permission)
RETURN m.display_name          AS mdm_profile,
       m.identifier            AS profile_id,
       m.organization          AS organization,
       r.flagged_bundle_id     AS interpreter_bundle_id,
       t.service               AS tcc_service,
       t.display_name          AS tcc_display_name
ORDER BY m.identifier ASC, t.service ASC
