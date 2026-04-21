// Name: Injectable Apps with iCloud Sync
// Purpose: Find injectable applications with iCloud container entitlements on hosts where iCloud is signed in — data exfiltration risk across all synced devices
// Category: Red Team
// Severity: High
// Parameters: none
// Prerequisites: import.py must have run
// CVE: CVE-2023-42926
// ATT&CK: T1537

MATCH (a:Application)-[:HAS_ENTITLEMENT]->(e:Entitlement {category: 'icloud'})
WHERE size(a.injection_methods) > 0
MATCH (a)-[:INSTALLED_ON]->(c:Computer {icloud_signed_in: true})
RETURN a.name            AS app,
       a.bundle_id       AS bundle_id,
       a.injection_methods AS injection_methods,
       collect(e.name)   AS icloud_entitlements,
       c.hostname        AS hostname,
       c.icloud_drive_enabled    AS drive_enabled,
       c.icloud_keychain_enabled AS keychain_sync
ORDER BY size(a.injection_methods) DESC, a.name
