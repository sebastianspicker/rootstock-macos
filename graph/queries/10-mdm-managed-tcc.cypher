// Name: MDM-Managed TCC Permissions
// Purpose: Find TCC grants silently enforced via MDM profiles (user-irrevocable)
// Category: Blue Team
// Severity: Informational
// Parameters: none
// Prerequisites: import.py must have run
//
// Finds TCC permissions that are silently enforced via MDM configuration profiles.
// MDM grants cannot be revoked by the user and take precedence over manual settings.
//
// High-value finding: injectable applications with MDM-granted TCC permissions
// are particularly dangerous — an attacker who injects into such an app inherits
// the silent MDM-granted access without any user prompt.
//
// Usage:
//   cypher-shell -u neo4j -p rootstock < graph/queries/10-mdm-managed-tcc.cypher
//   Or paste into Neo4j Browser.
// ATT&CK: T1548.004

MATCH (m:MDM_Profile)-[c:CONFIGURES]->(t:TCC_Permission)

// Check if the target app is also known and injectable
OPTIONAL MATCH (a:Application {bundle_id: c.bundle_id})

WITH m, c, t, a,
     a IS NOT NULL AND size(a.injection_methods) > 0 AS app_is_injectable

RETURN
    m.identifier        AS profile_identifier,
    m.display_name      AS profile_name,
    m.organization      AS organization,
    c.bundle_id         AS target_bundle_id,
    a.name              AS app_name,
    t.service           AS tcc_service,
    c.allowed           AS mdm_allowed,
    app_is_injectable

ORDER BY app_is_injectable DESC, m.identifier, c.bundle_id
LIMIT 100
