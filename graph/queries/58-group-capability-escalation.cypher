// Name: Group-Based Capability Escalation
// Purpose: Find users with debugger or remote access capabilities via group membership
// Category: Red Team
// Severity: High
// Parameters: none
// Prerequisites: import.py + infer.py must have run
// Attack: Group membership grants implicit capabilities (_developer → debug, access_ssh → SSH)

MATCH (u:User)-[:MEMBER_OF]->(g:LocalGroup)
WHERE g.name IN ['_developer', 'com.apple.access_ssh', 'com.apple.access_screensharing', 'admin']
OPTIONAL MATCH (u)-[:CAN_DEBUG]->(debuggable:Application)
WITH u,
     collect(DISTINCT g.name) AS capability_groups,
     count(debuggable) AS debuggable_apps
RETURN u.name                              AS username,
       capability_groups,
       'admin' IN capability_groups        AS is_admin,
       debuggable_apps                     AS debuggable_app_count
ORDER BY debuggable_apps DESC, u.name
