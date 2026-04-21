// Name: User-Centric Access Enumeration
// Purpose: Given a username, show all reachable TCC permissions, keychain items, and applications
// Category: Red Team
// Severity: High
// Parameters: $username (e.g. "admin")
// Attack: Enumerate everything a compromised user account can reach through group membership, sessions, sudo, and app relationships
// Prerequisites: import.py + infer.py must have run

MATCH (u:User {name: $username})

// Direct edges from user
OPTIONAL MATCH (u)-[:MEMBER_OF]->(g:LocalGroup)
OPTIONAL MATCH (u)-[:HAS_SESSION]->(s:LoginSession)
OPTIONAL MATCH (u)-[:SUDO_NOPASSWD]->(sr:SudoersRule)

// Apps running as this user (via launch items)
OPTIONAL MATCH (li:LaunchItem)-[:RUNS_AS]->(u)
OPTIONAL MATCH (app:Application)-[:PERSISTS_VIA]->(li)

// TCC grants reachable through those apps
OPTIONAL MATCH (app)-[:HAS_TCC_GRANT {allowed: true}]->(perm:TCC_Permission)

// Keychain items readable by those apps
OPTIONAL MATCH (app)-[:CAN_READ_KEYCHAIN]->(kc:Keychain_Item)

RETURN u.name                                                AS username,
       collect(DISTINCT g.name)                              AS groups,
       collect(DISTINCT s.terminal)                          AS sessions,
       collect(DISTINCT sr.key)                              AS sudo_rules,
       collect(DISTINCT app.bundle_id)                       AS apps_running_as_user,
       collect(DISTINCT perm.display_name)                   AS reachable_tcc,
       collect(DISTINCT kc.label)                            AS reachable_keychain
