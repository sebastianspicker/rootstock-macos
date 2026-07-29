// Name: Kerberos Ticket Access via Injectable Apps
// Purpose: Find modeled app-to-ccache read relationships for validation
// Category: Red Team
// Severity: Critical
// Parameters: none
// Prerequisites: import_scan.py + infer.py must have run
// CVE: CVE-2024-44245
// ATT&CK: T1558
// Validate process access, ticket contents, validity, and principal scope before
// concluding that a usable ticket can be obtained.

MATCH (a:Application)-[r:CAN_READ_KERBEROS]->(ka:KerberosArtifact {artifact_type: 'ccache'})
MATCH (u:User)-[:HAS_KERBEROS_CACHE]->(ka)
WHERE size(a.injection_methods) > 0
RETURN a.name               AS injectable_app,
       a.bundle_id          AS bundle_id,
       r.method             AS access_method,
       ka.path              AS ccache_path,
       ka.owner             AS ccache_owner,
       ka.is_world_readable AS world_readable,
       u.name               AS ad_user,
       u.is_ad_user         AS is_ad_user
ORDER BY a.name, u.name
