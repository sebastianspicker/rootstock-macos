// Name: AD Group Transitive macOS Access
// Purpose: AD group membership reaching macOS TCC grants — shows cross-domain privilege paths from AD groups through local users to sensitive macOS permissions
// Category: Red Team
// Severity: Critical
// Parameters: none
// Prerequisites: import.py must have run

MATCH (ad:ADUser)-[:AD_MEMBER_OF]->(ag:ADGroup)
MATCH (ad)-[:SAME_IDENTITY]->(u:User)
MATCH (app:Application)-[:PERSISTS_VIA]->(li:LaunchItem)-[:RUNS_AS]->(u)
MATCH (app)-[:HAS_TCC_GRANT {allowed: true}]->(tcc:TCC_Permission)
RETURN ag.name                              AS ad_group,
       ag.domain                            AS ad_domain,
       ad.name                              AS ad_user,
       u.name                               AS macos_user,
       app.name                             AS application,
       app.bundle_id                        AS bundle_id,
       collect(DISTINCT tcc.service)        AS tcc_grants,
       size(app.injection_methods) > 0      AS injectable
ORDER BY ag.name, ad.name, app.name
