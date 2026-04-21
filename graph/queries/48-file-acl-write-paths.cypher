// Name: Critical File Write Access Audit
// Purpose: Identify users who can write to TCC databases, sudoers, sshd_config, or other security-critical files
// Category: Blue Team
// Severity: Critical
// Parameters: none
// Prerequisites: import.py + infer.py must have run (with file_acls data)
// CVE: CVE-2024-23296, CVE-2023-40404
// ATT&CK: T1098

MATCH (u:User)-[w:CAN_WRITE]->(cf:CriticalFile)
OPTIONAL MATCH (cf)-[:PROTECTS]->(target)
RETURN u.name                              AS username,
       cf.path                             AS critical_file,
       cf.category                         AS category,
       cf.owner                            AS file_owner,
       cf.mode                             AS permissions,
       cf.is_sip_protected                 AS sip_protected,
       collect(DISTINCT coalesce(
           target.display_name, target.service, target.label, '?'
       ))                                  AS protects
ORDER BY cf.category, u.name
