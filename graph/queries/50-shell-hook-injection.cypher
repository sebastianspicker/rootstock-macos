// Name: Shell Hook Injection Paths
// Purpose: Identify writable shell hooks that enable credential theft and persistent code injection
// Category: Red Team
// Severity: High
// Parameters: none
// Attack: Writable .zshrc/.bashrc enables injecting keyloggers, credential harvesters, or SSH agent hijacking
// Prerequisites: import.py + infer.py must have run (with shell hook data)
// CVE: CVE-2023-32364
// ATT&CK: T1546.004

MATCH (u:User)-[r:CAN_INJECT_SHELL]->(cf:CriticalFile {category: 'shell_hook'})
OPTIONAL MATCH (u)-[:HAS_SESSION]->(s:LoginSession)
RETURN u.name                              AS username,
       cf.path                             AS shell_hook_path,
       cf.mode                             AS permissions,
       cf.owner                            AS file_owner,
       collect(DISTINCT s.session_type)    AS active_session_types,
       size(collect(DISTINCT s))           AS active_session_count
ORDER BY active_session_count DESC, u.name
