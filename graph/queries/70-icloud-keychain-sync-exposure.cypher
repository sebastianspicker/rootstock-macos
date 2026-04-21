// Name: iCloud Keychain Sync Exposure
// Purpose: Injectable apps with keychain read access on hosts where iCloud Keychain sync is enabled — compromised secrets propagate to all linked devices, multiplying blast radius
// Category: Red Team
// Severity: Critical
// Parameters: none
// Prerequisites: import.py must have run
// CVE: CVE-2024-44204
// ATT&CK: T1555.001, T1537

MATCH (a:Application)-[:CAN_READ_KEYCHAIN]->(k:Keychain_Item)
WHERE size(a.injection_methods) > 0
MATCH (a)-[:INSTALLED_ON]->(c:Computer {icloud_keychain_enabled: true})
RETURN a.name            AS app,
       a.bundle_id       AS bundle_id,
       a.injection_methods AS injection_methods,
       collect(DISTINCT k.label) AS readable_keychain_items,
       count(DISTINCT k) AS keychain_item_count,
       c.hostname        AS hostname
ORDER BY keychain_item_count DESC, a.name
