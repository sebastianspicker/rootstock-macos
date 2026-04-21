// Name: File Permission Escalation Chains
// Purpose: Full chain: user → write critical file → modify security policy → gain access to protected resources
// Category: Red Team
// Severity: Critical
// Parameters: none
// Attack: A user who can write TCC.db can grant themselves FDA; a user who can write sudoers can grant NOPASSWD
// Prerequisites: import.py + infer.py must have run (with file_acls data)
// CVE: CVE-2024-23296, CVE-2023-40404
// ATT&CK: T1098

// TCC database write → modify any TCC grant
MATCH (u:User)-[:CAN_MODIFY_TCC]->(perm:TCC_Permission)
RETURN u.name                              AS username,
       'TCC database write'                AS attack_vector,
       perm.display_name                   AS target_permission,
       perm.service                        AS target_service
ORDER BY u.name, perm.display_name
