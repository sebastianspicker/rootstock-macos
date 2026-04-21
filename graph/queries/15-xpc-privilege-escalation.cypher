// Name: XPC Service Privilege Escalation
// Purpose: XPC services with elevated entitlements reachable from injectable apps
// Category: Red Team
// Severity: High
// Parameters: none
// Prerequisites: import.py + infer.py must have run; Phase 3.1 (XPC) data required
//
// Attack: Injectable app → COMMUNICATES_WITH → XPC service with privileged entitlements
//         → attacker inherits XPC service capabilities via compromised client
//
// XPC services often hold elevated entitlements (TCC bypass, private APIs, root operations).
// An injectable app that communicates with such a service is a gateway to those capabilities.

MATCH (app:Application)-[:COMMUNICATES_WITH]->(xpc:XPC_Service)
MATCH (:Application {bundle_id: 'attacker.payload'})-[inj:CAN_INJECT_INTO]->(app)

// Check if the XPC service has elevated entitlements
WHERE size(xpc.entitlements) > 0

WITH app, xpc, collect(DISTINCT inj.method) AS injection_methods

// Also check TCC grants of the app for combined severity scoring
OPTIONAL MATCH (app)-[:HAS_TCC_GRANT {allowed: true}]->(perm:TCC_Permission)
WITH app, xpc, injection_methods, collect(DISTINCT perm.display_name) AS app_tcc_grants

RETURN app.name                AS app_name,
       app.bundle_id           AS bundle_id,
       xpc.label               AS xpc_service,
       xpc.program             AS xpc_program,
       xpc.type                AS xpc_type,
       xpc.entitlements        AS xpc_entitlements,
       injection_methods,
       app_tcc_grants,
       size(xpc.entitlements)  AS entitlement_count
ORDER BY entitlement_count DESC, app.name
LIMIT 50
