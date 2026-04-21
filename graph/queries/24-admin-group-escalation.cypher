// Name: Admin Group Privilege Escalation
// Purpose: Users in the admin group that own injectable apps — sudo escalation path
// Category: Red Team
// Severity: High
// Parameters: none
// Attack: Compromise injectable app owned by admin user → sudo -S → root escalation
// Prerequisites: import.py + infer.py must have run; groups module must have collected data
// ATT&CK: T1068, T1548.003

MATCH (u:User)-[:MEMBER_OF]->(g:LocalGroup {name: 'admin'})
MATCH (:Application {bundle_id: 'attacker.payload'})-[inj:CAN_INJECT_INTO]->(app:Application)
WHERE app.path STARTS WITH '/Users/' + u.name + '/'
   OR app.path STARTS WITH '/Applications/'
WITH u, g,
     collect(DISTINCT app.name)           AS injectable_apps,
     collect(DISTINCT app.bundle_id)      AS injectable_bundle_ids,
     collect(DISTINCT inj.method)         AS injection_methods
WHERE size(injectable_apps) > 0
RETURN u.name                             AS admin_user,
       g.gid                              AS group_gid,
       injectable_apps,
       injectable_bundle_ids,
       injection_methods,
       size(injectable_apps)              AS injectable_app_count
ORDER BY injectable_app_count DESC, admin_user ASC
