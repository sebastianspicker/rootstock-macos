// Name: Firewall-Exposed Injectable Apps
// Purpose: Injectable apps with firewall allowing inbound connections — network-reachable targets
// Category: Red Team
// Severity: High
// Parameters: none
// Attack: Network → inbound connection to app → inject code → TCC escalation
// Prerequisites: import.py + infer.py must have run; firewall module collected
// ATT&CK: T1190

MATCH (:Application {bundle_id: 'attacker.payload'})-[inj:CAN_INJECT_INTO]->(app:Application)
MATCH (app)-[fw:HAS_FIREWALL_RULE]->(f:FirewallPolicy)
WHERE fw.allow_incoming = true
WITH app, collect(DISTINCT inj.method) AS injection_methods
OPTIONAL MATCH (app)-[:HAS_TCC_GRANT {allowed: true}]->(t:TCC_Permission)
WITH app, injection_methods,
     collect(DISTINCT t.display_name) AS tcc_permissions
RETURN app.name                       AS app_name,
       app.bundle_id                  AS bundle_id,
       app.path                       AS path,
       app.team_id                    AS team_id,
       injection_methods,
       tcc_permissions,
       size(tcc_permissions)          AS permission_count,
       size(injection_methods)        AS method_count
ORDER BY permission_count DESC, method_count DESC, app.name ASC
