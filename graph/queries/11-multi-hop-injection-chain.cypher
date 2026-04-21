// Name: Multi-hop Injection + Apple Event Privilege Escalation
// Purpose: Find chains where attacker injects App A, App A automates App B, App B has FDA
// Category: Red Team
// Severity: Critical
// Parameters: $target_service (default: kTCCServiceSystemPolicyAllFiles)
// Prerequisites: import.py + infer.py must have run
// CVE: CVE-2025-31191, CVE-2024-44168
// ATT&CK: T1574.006, T1059.002
//
// Attack: attacker → CAN_INJECT_INTO → App A → CAN_SEND_APPLE_EVENT → App B → HAS_TCC_GRANT → FDA
// This combines injection with Apple Event automation for multi-vector privilege escalation.

MATCH (attacker:Application {bundle_id: 'attacker.payload'})
      -[:CAN_INJECT_INTO]->(app_a:Application)
      -[:CAN_SEND_APPLE_EVENT]->(app_b:Application)
      -[:HAS_TCC_GRANT {allowed: true}]->(perm:TCC_Permission)
WHERE perm.service = coalesce($target_service, 'kTCCServiceSystemPolicyAllFiles')
  AND app_a.bundle_id <> app_b.bundle_id
RETURN attacker.name               AS attacker,
       app_a.name                  AS inject_target,
       app_a.bundle_id             AS inject_bundle_id,
       app_a.injection_methods     AS injection_methods,
       app_b.name                  AS automation_target,
       app_b.bundle_id             AS automation_bundle_id,
       perm.display_name           AS final_permission,
       perm.service                AS final_service
ORDER BY app_a.name, app_b.name
