// Name: Cross-Host Injection Chain (SSH + Injectable FDA)
// Purpose: Find paths where SSH access to a remote host enables injection of FDA apps on that host
// Category: Red Team
// Severity: Critical
// Parameters: none
// Attack: SSH to Host B + injectable FDA apps on Host B = remote privilege escalation
// Prerequisites: merge_scans.py must have been used to import scans from multiple hosts; infer.py must have run
// ATT&CK: T1021.004

MATCH (u:User)-[:LOCAL_TO]->(src:Computer)
MATCH (u)-[:LOCAL_TO]->(dst:Computer)
WHERE src <> dst
MATCH (remote_svc:RemoteAccessService {service: 'ssh', enabled: true})-[:ACCESSIBLE_BY]->(remote_u:User)-[:LOCAL_TO]->(dst)
MATCH (target:Application)-[:INSTALLED_ON]->(dst)
MATCH (:Application {bundle_id: 'attacker.payload'})-[:CAN_INJECT_INTO]->(target)
MATCH (target)-[:HAS_TCC_GRANT {allowed: true}]->(perm:TCC_Permission)
RETURN u.name                              AS username,
       src.hostname                        AS source_host,
       dst.hostname                        AS target_host,
       target.name                         AS injectable_app,
       target.bundle_id                    AS bundle_id,
       collect(DISTINCT perm.display_name) AS tcc_grants
ORDER BY u.name, dst.hostname
