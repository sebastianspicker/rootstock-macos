// Name: Multi-hop Injection Chain
// Purpose: Find chains of injectable apps leading to high-value TCC permissions
// Category: Red Team
// Severity: Critical
// Parameters: none
// Attack: Attacker → inject App1 → App1 has TCC → escalate to critical permission
//         Or: Attacker → inject App1 → App1 can inject App2 (deeper chain)
// Prerequisites: import.py + infer.py must have run

MATCH path = (attacker:Application {bundle_id: 'attacker.payload'})
             -[:CAN_INJECT_INTO*1..3]->
             (target:Application)-[:HAS_TCC_GRANT {allowed: true}]->(perm:TCC_Permission)
WHERE perm.service IN [
    'kTCCServiceSystemPolicyAllFiles',
    'kTCCServiceAccessibility',
    'kTCCServiceScreenCapture',
    'kTCCServiceEndpointSecurityClient',
    'kTCCServiceListenEvent'
]
WITH path, target, perm,
     [n IN nodes(path) | coalesce(n.name, n.display_name, '?')] AS chain,
     length(path) AS hops
RETURN chain,
       target.name             AS terminal_app,
       target.bundle_id        AS terminal_bundle_id,
       perm.display_name       AS terminal_permission,
       hops
ORDER BY hops ASC, perm.display_name ASC
LIMIT 20
