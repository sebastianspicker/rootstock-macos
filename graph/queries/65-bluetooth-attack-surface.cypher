// Name: Bluetooth Attack Surface
// Purpose: Paired BT devices cross-referenced with injectable apps holding Bluetooth TCC grants
// Category: Red Team
// Severity: High
// Parameters: none
// Prerequisites: import.py must have run
// Attack: Physical proximity → paired BT device → inject BT-TCC app → gain Bluetooth access
// CVE: CVE-2023-45866
// ATT&CK: T1200

MATCH (bt:BluetoothDevice)-[:PAIRED_WITH]->(c:Computer)
OPTIONAL MATCH (a:Application)-[:HAS_TCC_GRANT {allowed: true}]->(t:TCC_Permission {service: 'kTCCServiceBluetoothAlways'})
WHERE size(a.injection_methods) > 0
WITH bt, c,
     collect(DISTINCT a.name)              AS injectable_bt_apps,
     collect(DISTINCT a.bundle_id)         AS injectable_bt_bundle_ids
RETURN bt.name                             AS device_name,
       bt.address                          AS device_address,
       bt.device_type                      AS device_type,
       bt.connected                        AS currently_connected,
       c.hostname                          AS host,
       c.bluetooth_discoverable            AS host_discoverable,
       injectable_bt_apps,
       size(injectable_bt_apps)            AS injectable_bt_app_count
ORDER BY injectable_bt_app_count DESC, bt.connected DESC
