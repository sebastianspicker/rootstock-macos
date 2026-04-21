// Name: Cross-Host User Presence (Lateral Movement Indicators)
// Purpose: Find users present on multiple hosts — potential lateral movement paths
// Category: Red Team
// Severity: High
// Parameters: none
// Attack: A user account on multiple hosts enables lateral movement via SSH, shared credentials, or key reuse
// Prerequisites: merge_scans.py must have been used to import scans from multiple hosts
// ATT&CK: T1021.004

MATCH (u:User)-[:LOCAL_TO]->(c:Computer)
WITH u, collect(DISTINCT c.hostname) AS hosts, count(DISTINCT c) AS host_count
WHERE host_count > 1
OPTIONAL MATCH (u)-[:MEMBER_OF]->(g:LocalGroup)
OPTIONAL MATCH (u)-[:SUDO_NOPASSWD]->(sr:SudoersRule)
RETURN u.name                              AS username,
       hosts,
       host_count,
       collect(DISTINCT g.name)            AS groups,
       count(DISTINCT sr)                  AS sudo_rules
ORDER BY host_count DESC, u.name
