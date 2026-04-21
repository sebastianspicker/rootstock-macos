// Name: Weak Physical Security Posture
// Purpose: Hosts with physical security weaknesses — no lockdown mode, BT discoverable, no screen lock, etc.
// Category: Blue Team
// Severity: High
// Parameters: none
// Prerequisites: import.py must have run
// CVE: CVE-2023-42861
// ATT&CK: T1200

MATCH (c:Computer)
WITH c,
     CASE WHEN c.lockdown_mode_enabled = false OR c.lockdown_mode_enabled IS NULL THEN 1 ELSE 0 END AS no_lockdown,
     CASE WHEN c.bluetooth_discoverable = true THEN 1 ELSE 0 END AS bt_discoverable,
     CASE WHEN c.screen_lock_enabled = false OR c.screen_lock_enabled IS NULL THEN 1 ELSE 0 END AS no_screen_lock,
     CASE WHEN c.screen_lock_delay > 5 THEN 1 ELSE 0 END AS slow_screen_lock,
     CASE WHEN c.display_sleep_timeout > 15 THEN 1 ELSE 0 END AS long_display_sleep,
     CASE WHEN c.filevault_enabled = false OR c.filevault_enabled IS NULL THEN 1 ELSE 0 END AS no_filevault,
     CASE WHEN c.secure_boot_level IS NOT NULL AND c.secure_boot_level <> 'full' THEN 1 ELSE 0 END AS weak_secure_boot,
     CASE WHEN c.external_boot_allowed = true THEN 1 ELSE 0 END AS ext_boot
WITH c,
     no_lockdown + bt_discoverable + no_screen_lock + slow_screen_lock +
     long_display_sleep + no_filevault + weak_secure_boot + ext_boot AS weakness_score,
     [x IN [
       CASE WHEN c.lockdown_mode_enabled = false OR c.lockdown_mode_enabled IS NULL THEN 'no_lockdown_mode' END,
       CASE WHEN c.bluetooth_discoverable = true THEN 'bluetooth_discoverable' END,
       CASE WHEN c.screen_lock_enabled = false OR c.screen_lock_enabled IS NULL THEN 'no_screen_lock' END,
       CASE WHEN c.screen_lock_delay > 5 THEN 'slow_screen_lock_delay' END,
       CASE WHEN c.display_sleep_timeout > 15 THEN 'long_display_sleep' END,
       CASE WHEN c.filevault_enabled = false OR c.filevault_enabled IS NULL THEN 'no_filevault' END,
       CASE WHEN c.secure_boot_level IS NOT NULL AND c.secure_boot_level <> 'full' THEN 'weak_secure_boot' END,
       CASE WHEN c.external_boot_allowed = true THEN 'external_boot_allowed' END
     ] WHERE x IS NOT NULL] AS weaknesses
WHERE weakness_score > 0
RETURN c.hostname       AS hostname,
       weakness_score,
       weaknesses,
       c.lockdown_mode_enabled   AS lockdown_mode,
       c.bluetooth_discoverable  AS bt_discoverable,
       c.screen_lock_enabled     AS screen_lock,
       c.screen_lock_delay       AS screen_lock_delay_sec,
       c.display_sleep_timeout   AS display_sleep_min,
       c.filevault_enabled       AS filevault,
       c.secure_boot_level       AS secure_boot,
       c.external_boot_allowed   AS external_boot
ORDER BY weakness_score DESC
