// Name: Hijackable Launch Daemons
// Purpose: Find root-level LaunchDaemons whose program binary is writable by non-root users
// Category: Red Team
// Severity: Critical
// Parameters: none
// Attack: Replace writable daemon binary with attacker payload → code runs as root on next launchd restart
// CVE: CVE-2024-44217
// ATT&CK: T1547.011, T1543.004
// Prerequisites: import.py must have run

MATCH (l:LaunchItem)
WHERE l.type = 'daemon'
  AND l.program_writable_by_non_root = true
OPTIONAL MATCH (a:Application)-[:PERSISTS_VIA]->(l)
OPTIONAL MATCH (u:User)-[:CAN_HIJACK]->(l)
RETURN l.label              AS daemon_label,
       l.program            AS program_path,
       l.plist_owner        AS plist_owner,
       l.program_owner      AS program_owner,
       l.run_at_load        AS auto_start,
       a.name               AS associated_app,
       a.bundle_id          AS app_bundle_id,
       collect(DISTINCT u.name) AS hijackable_by_users
ORDER BY l.run_at_load DESC, l.label ASC
