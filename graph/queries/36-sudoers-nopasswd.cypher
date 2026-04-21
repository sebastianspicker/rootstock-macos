// Name: Sudoers NOPASSWD Rules
// Purpose: Find sudoers rules that allow password-less privilege escalation
// Category: Red Team
// Severity: High
// Parameters: none
// Attack: Use NOPASSWD sudo rule to execute privileged commands without authentication
// ATT&CK: T1548.003
// Prerequisites: import.py must have run

MATCH (u:User)-[:SUDO_NOPASSWD]->(sr:SudoersRule)
RETURN u.name       AS username,
       sr.host      AS host,
       sr.command   AS command,
       sr.nopasswd  AS nopasswd,
       CASE
         WHEN sr.command = 'ALL' THEN 'Critical: unrestricted sudo without password'
         ELSE 'High: password-less sudo for specific command'
       END AS risk_assessment
ORDER BY sr.command = 'ALL' DESC, u.name ASC
