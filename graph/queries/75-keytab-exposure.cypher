// Name: Machine Keytab Exposure
// Purpose: Checks whether machine keytabs are world-readable or accessible via injection — a leaked keytab allows impersonating the machine account in AD
// Category: Blue Team
// Severity: High
// Parameters: none
// Prerequisites: import.py + infer.py must have run

MATCH (ka:KerberosArtifact {artifact_type: 'keytab'})
OPTIONAL MATCH (a:Application)-[r:CAN_READ_KERBEROS]->(ka)
WHERE size(a.injection_methods) > 0
RETURN ka.path              AS keytab_path,
       ka.owner             AS owner,
       ka.mode              AS permissions,
       ka.is_world_readable AS world_readable,
       collect(DISTINCT {app: a.name, method: r.method}) AS injectable_readers
ORDER BY ka.path
