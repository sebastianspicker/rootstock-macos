// Name: Injectable Apps Sharing Keychain Groups
// Purpose: Find injectable apps that share Keychain access groups with other apps
// Category: Red Team
// Severity: High
// Parameters: none
// Attack: Inject into app → read Keychain secrets shared with other apps in same access group
// CVE: CVE-2024-44204
// ATT&CK: T1555.001
// Prerequisites: import.py + infer.py must have run

MATCH (:Application {bundle_id: 'attacker.payload'})-[inj:CAN_INJECT_INTO]->(a:Application)
MATCH (a)-[skg:SHARES_KEYCHAIN_GROUP]-(b:Application)
WHERE a <> b
OPTIONAL MATCH (a)-[:CAN_READ_KEYCHAIN]->(k:Keychain_Item)
RETURN a.name                           AS injectable_app,
       a.bundle_id                      AS injectable_bundle_id,
       collect(DISTINCT inj.method)     AS injection_methods,
       b.name                           AS shared_with_app,
       b.bundle_id                      AS shared_with_bundle_id,
       skg.access_group                 AS shared_access_group,
       collect(DISTINCT k.label)        AS accessible_keychain_items
ORDER BY a.name ASC, b.name ASC
