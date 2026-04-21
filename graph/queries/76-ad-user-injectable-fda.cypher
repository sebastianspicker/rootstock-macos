// Name: AD Users with Injectable FDA Apps
// Purpose: AD users whose sessions include injectable FDA apps — injecting the app yields Full Disk Access plus the user's Kerberos tickets
// Category: Red Team
// Severity: Critical
// Parameters: none
// Prerequisites: import.py + infer.py must have run

MATCH (u:User {is_ad_user: true})-[:HAS_KERBEROS_CACHE]->(ka:KerberosArtifact)
MATCH (a:Application)-[:HAS_TCC_GRANT {allowed: true}]->(t:TCC_Permission {service: 'kTCCServiceSystemPolicyAllFiles'})
WHERE size(a.injection_methods) > 0
  AND NOT coalesce(a.is_sip_protected, false)
MATCH (a)-[r:CAN_READ_KERBEROS]->(ka)
RETURN u.name               AS ad_user,
       a.name               AS fda_app,
       a.bundle_id          AS bundle_id,
       a.injection_methods  AS injection_methods,
       ka.path              AS ccache_path,
       r.method             AS access_method
ORDER BY u.name, a.name
