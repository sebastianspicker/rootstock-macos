// Name: Accessibility API Abuse — Injectable Apps with GUI Control
// Purpose: Find injectable apps with Accessibility permission that can control other apps via simulated input
// Category: Red Team
// Severity: Critical
// Parameters: none
// Prerequisites: import.py + infer.py must have run
// Attack: Accessibility API grants full GUI control (keyboard, mouse, UI reading) — a superset of Apple Events
// CVE: CVE-2023-42937
// ATT&CK: T1056.002

MATCH (a:Application)-[:CAN_CONTROL_VIA_A11Y]->(target:Application)
MATCH (a)-[:HAS_TCC_GRANT {allowed: true}]->(:TCC_Permission {service: 'kTCCServiceAccessibility'})
OPTIONAL MATCH (target)-[:HAS_TCC_GRANT {allowed: true}]->(perm:TCC_Permission)
RETURN a.name                              AS a11y_app,
       a.bundle_id                         AS a11y_bundle_id,
       a.injection_methods                 AS injection_methods,
       target.name                         AS target_app,
       target.bundle_id                    AS target_bundle_id,
       collect(DISTINCT perm.display_name) AS target_tcc_grants
ORDER BY size(a.injection_methods) DESC, a.name
