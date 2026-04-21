// Name: MDM-Managed vs User-Granted TCC Comparison
// Purpose: Compare MDM-enforced TCC grants against user-granted ones for compliance
// Category: Blue Team
// Severity: Informational
// Parameters: none
// Prerequisites: import.py must have run; Phase 3.4 (MDM) data enhances results
//
// Use case: Enterprise compliance — verify that expected apps are MDM-managed
// and that no unexpected user-granted permissions have been added outside policy.
//
// MDM grants (auth_reason=4) take precedence over user grants and cannot be revoked
// by the user via System Settings. User grants (auth_reason=1) can be revoked.

MATCH (app:Application)-[r:HAS_TCC_GRANT {allowed: true}]->(perm:TCC_Permission)
WITH perm.display_name AS permission,
     perm.service      AS service,
     sum(CASE WHEN r.auth_reason = 'mdm' THEN 1 ELSE 0 END) AS mdm_granted,
     sum(CASE WHEN r.auth_reason = 'user_prompt' THEN 1 ELSE 0 END) AS user_granted,
     sum(CASE WHEN r.auth_reason = 'entitlement' THEN 1 ELSE 0 END) AS entitlement_granted,
     sum(CASE WHEN r.auth_reason = 'system' THEN 1 ELSE 0 END) AS system_granted,
     count(*) AS total_grants

RETURN permission,
       service,
       mdm_granted,
       user_granted,
       entitlement_granted,
       system_granted,
       total_grants,
       // Flag: services where user grants exist outside MDM policy
       CASE WHEN user_granted > 0 AND mdm_granted = 0 THEN true ELSE false END AS user_only_no_mdm_policy
ORDER BY user_granted DESC, total_grants DESC
