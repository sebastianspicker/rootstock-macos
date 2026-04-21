// Name: Remote Access Attack Surface
// Purpose: SSH/Screen Sharing enabled with injectable apps accessible by remote users
// Category: Red Team
// Severity: High
// Parameters: none
// Attack: Remote login via SSH/VNC → exploit injectable app → TCC privilege escalation
// Prerequisites: import.py + infer.py must have run; remote access + groups modules collected
// ATT&CK: T1021.004, T1021.005

MATCH (svc:RemoteAccessService)
WHERE svc.enabled = true
OPTIONAL MATCH (svc)-[:ACCESSIBLE_BY]->(u:User)
WITH svc, collect(DISTINCT u.name) AS remote_users
// Find injectable apps available to any user on this system
OPTIONAL MATCH (:Application {bundle_id: 'attacker.payload'})-[inj:CAN_INJECT_INTO]->(app:Application)
WITH svc, remote_users,
     collect(DISTINCT app.name)           AS injectable_apps,
     collect(DISTINCT inj.method)         AS injection_methods
RETURN svc.service                        AS service,
       svc.port                           AS port,
       remote_users,
       size(remote_users)                 AS remote_user_count,
       injectable_apps,
       injection_methods,
       size(injectable_apps)              AS injectable_app_count
ORDER BY injectable_app_count DESC
