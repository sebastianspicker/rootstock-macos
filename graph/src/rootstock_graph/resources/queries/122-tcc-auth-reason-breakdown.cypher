// Name: TCC Auth Reason Breakdown (Blue Team)
// Purpose: Allowed TCC grants by auth reason: user-granted vs MDM-managed vs entitlement-based
// Category: Blue Team
// Severity: Informational
// Parameters: none
// Use case: Separate user consent from managed or entitlement grants; split from 07
// Prerequisites: rootstock-graph-import-scan must have run

MATCH (app:Application)-[r:HAS_TCC_GRANT {allowed: true}]->(perm:TCC_Permission)
WITH r.auth_reason AS granted_by, count(*) AS n
RETURN granted_by, n
ORDER BY n DESC
