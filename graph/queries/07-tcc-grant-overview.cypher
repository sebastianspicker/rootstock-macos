// Name: TCC Grant Overview (Blue Team)
// Purpose: Summary of all TCC grants — useful for security audits and baseline establishment
// Category: Blue Team
// Severity: Informational
// Parameters: none
// Use case: Enumerate the full TCC attack surface; identify anomalies and over-privileged apps
// Prerequisites: import.py must have run

// ── Section 1: Grants per permission type ─────────────────────────────────
// Run this block alone to see the distribution of TCC permissions.

MATCH (app:Application)-[r:HAS_TCC_GRANT]->(perm:TCC_Permission)
WITH perm.display_name AS permission,
     perm.service      AS service,
     sum(CASE WHEN r.allowed = true  THEN 1 ELSE 0 END) AS allowed_count,
     sum(CASE WHEN r.allowed = false THEN 1 ELSE 0 END) AS denied_count,
     count(*) AS total_grants
RETURN permission, service, allowed_count, denied_count, total_grants
ORDER BY total_grants DESC;

// ── Section 2: Most-permissioned apps ─────────────────────────────────────
// Run this block to find apps with the most TCC grants (potential over-privileging).

MATCH (app:Application)-[r:HAS_TCC_GRANT {allowed: true}]->(perm:TCC_Permission)
WITH app, collect(DISTINCT perm.display_name) AS permissions
RETURN app.name            AS app_name,
       app.bundle_id       AS bundle_id,
       app.is_system       AS is_system,
       permissions,
       size(permissions)   AS permission_count
ORDER BY permission_count DESC
LIMIT 20;

// ── Section 3: Auth reason breakdown ──────────────────────────────────────
// Distinguish user-granted vs MDM-managed vs entitlement-based permissions.

MATCH (app:Application)-[r:HAS_TCC_GRANT {allowed: true}]->(perm:TCC_Permission)
WITH r.auth_reason AS granted_by, count(*) AS n
RETURN granted_by, n
ORDER BY n DESC;
