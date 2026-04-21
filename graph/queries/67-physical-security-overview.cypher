// Name: Physical Security Overview
// Purpose: Complete physical posture inventory per host with all BT devices and posture properties
// Category: Blue Team
// Severity: Informational
// Parameters: none
// Prerequisites: import.py must have run

MATCH (c:Computer)
OPTIONAL MATCH (bt:BluetoothDevice)-[:PAIRED_WITH]->(c)
WITH c,
     collect({
       name: bt.name,
       address: bt.address,
       type: bt.device_type,
       connected: bt.connected
     }) AS bluetooth_devices,
     count(bt) AS bt_device_count
RETURN c.hostname                    AS hostname,
       c.lockdown_mode_enabled       AS lockdown_mode,
       c.bluetooth_enabled           AS bluetooth_enabled,
       c.bluetooth_discoverable      AS bluetooth_discoverable,
       bt_device_count,
       bluetooth_devices,
       c.screen_lock_enabled         AS screen_lock,
       c.screen_lock_delay           AS screen_lock_delay_sec,
       c.display_sleep_timeout       AS display_sleep_min,
       c.thunderbolt_security_level  AS thunderbolt_security,
       c.secure_boot_level           AS secure_boot,
       c.external_boot_allowed       AS external_boot,
       c.filevault_enabled           AS filevault,
       c.sip_enabled                 AS sip,
       c.gatekeeper_enabled          AS gatekeeper
ORDER BY c.hostname
