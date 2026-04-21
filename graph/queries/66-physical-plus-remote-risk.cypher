// Name: Physical + Remote Combined Risk
// Purpose: Hosts with weak physical posture AND enabled remote access — maximum exposure
// Category: Blue Team
// Severity: Critical
// Parameters: none
// Prerequisites: import.py must have run

MATCH (c:Computer)
WHERE (c.lockdown_mode_enabled IS NULL OR c.lockdown_mode_enabled = false)
  AND (c.screen_lock_enabled IS NULL OR c.screen_lock_enabled = false
       OR c.screen_lock_delay > 5
       OR c.display_sleep_timeout > 15)
WITH c
MATCH (svc:RemoteAccessService)
WHERE svc.enabled = true
// Scope remote access service to this host via user LOCAL_TO relationship
MATCH (svc)-[:ACCESSIBLE_BY]->(u:User)-[:LOCAL_TO]->(c)
WITH c, svc, collect(DISTINCT u.name) AS remote_users
RETURN c.hostname              AS hostname,
       c.lockdown_mode_enabled AS lockdown_mode,
       c.screen_lock_enabled   AS screen_lock,
       c.screen_lock_delay     AS screen_lock_delay_sec,
       c.filevault_enabled     AS filevault,
       svc.service             AS remote_service,
       svc.port                AS port,
       remote_users,
       size(remote_users)      AS remote_user_count
ORDER BY remote_user_count DESC
