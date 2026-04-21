// Name: Keychain Crown Jewels — High-Sensitivity Items
// Purpose: Identify high-sensitivity keychain items (SSH keys, certificates) and who can access them
// Category: Blue Team
// Severity: High
// Parameters: none
// Prerequisites: import.py must have run
// Forensic: Prioritize keychain items by sensitivity tier — SSH keys and certificates are higher value than saved passwords
// CVE: CVE-2024-44204
// ATT&CK: T1555.001

MATCH (k:Keychain_Item)
OPTIONAL MATCH (app:Application)-[:CAN_READ_KEYCHAIN]->(k)
RETURN k.label                             AS item_label,
       k.kind                              AS item_kind,
       k.service                           AS service,
       coalesce(k.sensitivity, 'low')      AS sensitivity_tier,
       collect(DISTINCT app.name)          AS trusted_apps,
       count(app)                          AS trusted_app_count
ORDER BY
    CASE coalesce(k.sensitivity, 'low')
        WHEN 'critical' THEN 0
        WHEN 'high' THEN 1
        WHEN 'medium' THEN 2
        ELSE 3
    END,
    k.label
