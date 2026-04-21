// Name: Transitive FDA via Apple Events / Finder Automation
// Purpose: Apps that can script Finder (or other targets) to gain transitive Full Disk Access
// Category: Red Team
// Severity: Critical
// Parameters: none
// Attack: Inject into app with AppleEvents grant → script Finder → read/write any file
// CVE: CVE-2024-44206
// ATT&CK: T1059.002
// Prerequisites: import.py + infer.py must have run

MATCH (a:Application)-[r:HAS_TRANSITIVE_FDA]->(fda:TCC_Permission {service: 'kTCCServiceSystemPolicyAllFiles'})
OPTIONAL MATCH (:Application {bundle_id: 'attacker.payload'})-[inj:CAN_INJECT_INTO]->(a)
RETURN a.name                       AS app_name,
       a.bundle_id                  AS bundle_id,
       a.path                       AS path,
       a.is_sandboxed               AS sandboxed,
       CASE WHEN inj IS NOT NULL THEN true ELSE false END AS injectable,
       collect(DISTINCT inj.method) AS injection_methods
ORDER BY injectable DESC, a.name ASC
