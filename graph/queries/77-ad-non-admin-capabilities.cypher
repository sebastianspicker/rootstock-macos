// Name: AD Users in Non-Admin Capability Groups
// Purpose: AD users who gained membership in capability-granting groups (e.g. _developer, wheel) via AD — each group grants distinct escalation paths
// Note: CAN_DEBUG edges require infer_group_capabilities.py to have run first (pipeline default)
// Category: Red Team
// Severity: High
// Parameters: none
// Prerequisites: import.py + infer.py must have run

MATCH (u:User {is_ad_user: true})-[:MEMBER_OF]->(lg:LocalGroup)
WHERE lg.name <> 'admin'
OPTIONAL MATCH (u)-[:CAN_DEBUG]->(a:Application)
RETURN u.name                      AS ad_user,
       lg.name                     AS local_group,
       CASE lg.name
         WHEN '_developer' THEN 'CAN_DEBUG (task_for_pid)'
         WHEN 'wheel'      THEN 'root-equivalent via su/sudo'
         WHEN 'staff'      THEN 'local file access'
         WHEN 'com.apple.access_ssh'            THEN 'SSH access'
         WHEN 'com.apple.access_screensharing'  THEN 'Screen Sharing access'
         ELSE 'group membership'
       END                         AS implied_capability,
       collect(DISTINCT a.bundle_id) AS debuggable_apps
ORDER BY lg.name, u.name
