// Name: AD-Bound Mac Attack Surface
// Purpose: AD-bound hosts with injectable apps that can access Kerberos tickets — cross-boundary bridge for lateral movement into Active Directory
// Category: Red Team
// Severity: Critical
// Parameters: none
// Prerequisites: import.py + infer.py must have run

MATCH (c:Computer {ad_bound: true})
MATCH (a:Application)-[:INSTALLED_ON]->(c)
WHERE size(a.injection_methods) > 0
  AND NOT coalesce(a.is_sip_protected, false)
OPTIONAL MATCH (a)-[r:CAN_READ_KERBEROS]->(ka:KerberosArtifact)
RETURN c.hostname           AS host,
       c.ad_realm           AS ad_realm,
       a.name               AS app,
       a.bundle_id          AS bundle_id,
       a.injection_methods  AS injection_methods,
       collect(DISTINCT ka.path) AS accessible_kerberos_artifacts
ORDER BY size(collect(DISTINCT ka.path)) DESC, a.name
