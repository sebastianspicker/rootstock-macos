// Name: Private Apple Entitlement Audit
// Purpose: Find third-party apps with private Apple entitlements (high-value targets)
// Category: Red Team
// Severity: High
// Parameters: none
// Attack: Private entitlements grant elevated privileges not available to normal apps.
//         If the app is also injectable, an attacker inherits those privileges.
// Prerequisites: import.py must have run

MATCH (app:Application {is_system: false})-[:HAS_ENTITLEMENT]->(ent:Entitlement {is_private: true})
WITH app, collect(DISTINCT ent.name) AS private_entitlements
RETURN app.name                          AS app_name,
       app.bundle_id                     AS bundle_id,
       app.signed                        AS signed,
       app.team_id                       AS team_id,
       private_entitlements,
       size(app.injection_methods) > 0   AS is_injectable,
       app.injection_methods             AS injection_methods,
       size(private_entitlements)        AS private_ent_count
ORDER BY private_ent_count DESC, app.name ASC
