// Name: XPC Service Privilege Escalation
// Purpose: XPC services with elevated entitlements reachable from injectable apps
// Category: Red Team
// Severity: High
// Parameters: none
// Prerequisites: import_scan.py + infer.py must have run; XPC collector data required
//
// Attack model: injection relationship → COMMUNICATES_WITH → XPC service entitlements
//
// A result does not establish that the client can invoke a privileged operation. Validate
// the service interface, authorization checks, caller identity, and entitlement behavior.

MATCH (app:Application)-[:COMMUNICATES_WITH]->(xpc:XPC_Service)
MATCH (:Application {bundle_id: 'attacker.payload'})-[inj:CAN_INJECT_INTO]->(app)

// Check if the XPC service has elevated entitlements
WHERE size(xpc.entitlements) > 0

WITH app, xpc, collect(DISTINCT inj.method) AS injection_methods

// Also return TCC grants held by the application for review.
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
