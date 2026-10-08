// Name: Host Security Settings Overview
// Purpose: One row per account, remote-control, Software Update and malware-protection setting with its value and a plain assessment (weak / ok / unknown)
// Category: Blue Team
// Severity: High
// Parameters: none
// ATT&CK: T1078, T1021, T1562.001
// Prerequisites: rootstock-graph-import-scan must have run

MATCH (c:Computer)
UNWIND [
  {rank: 1, setting: 'Guest account enabled', value: c.guest_account_enabled, weak: c.guest_account_enabled = true, known: c.guest_account_enabled IS NOT NULL},
  {rank: 2, setting: 'Automatic login user', value: c.auto_login_user, weak: c.auto_login_user IS NOT NULL, known: c.auto_login_user IS NOT NULL OR c.guest_account_enabled IS NOT NULL},
  {rank: 3, setting: 'Root account enabled', value: c.root_account_enabled, weak: c.root_account_enabled = true, known: c.root_account_enabled IS NOT NULL},
  {rank: 4, setting: 'Remote Apple Events enabled', value: c.remote_apple_events_enabled, weak: c.remote_apple_events_enabled = true, known: c.remote_apple_events_enabled IS NOT NULL},
  {rank: 5, setting: 'Remote Management enabled', value: c.remote_management_enabled, weak: c.remote_management_enabled = true, known: c.remote_management_enabled IS NOT NULL},
  {rank: 6, setting: 'Software Update: automatic check', value: c.software_update_automatic_check, weak: c.software_update_automatic_check = false, known: c.software_update_automatic_check IS NOT NULL},
  {rank: 7, setting: 'Software Update: automatic download', value: c.software_update_automatic_download, weak: c.software_update_automatic_download = false, known: c.software_update_automatic_download IS NOT NULL},
  {rank: 8, setting: 'Software Update: install security responses', value: c.software_update_install_security_responses, weak: c.software_update_install_security_responses = false, known: c.software_update_install_security_responses IS NOT NULL},
  {rank: 9, setting: 'Software Update: install macOS updates', value: c.software_update_install_system_updates, weak: c.software_update_install_system_updates = false, known: c.software_update_install_system_updates IS NOT NULL},
  {rank: 10, setting: 'Software Update: install app updates', value: c.software_update_install_app_updates, weak: c.software_update_install_app_updates = false, known: c.software_update_install_app_updates IS NOT NULL},
  {rank: 11, setting: 'Software Update: last successful check', value: c.software_update_last_successful_check, weak: false, known: c.software_update_last_successful_check IS NOT NULL},
  {rank: 12, setting: 'XProtect version', value: c.xprotect_version, weak: false, known: c.xprotect_version IS NOT NULL},
  {rank: 13, setting: 'XProtect Remediator version', value: c.xprotect_remediator_version, weak: false, known: c.xprotect_remediator_version IS NOT NULL},
  {rank: 14, setting: 'MRT version', value: c.mrt_version, weak: false, known: c.mrt_version IS NOT NULL}
] AS row
WITH c, row,
     CASE
       WHEN coalesce(row.weak, false) THEN 'weak'
       WHEN row.known THEN 'ok'
       ELSE 'unknown'
     END AS assessment
RETURN c.hostname               AS hostname,
       row.setting              AS setting,
       toString(row.value)      AS value,
       assessment,
       row.rank                 AS rank
ORDER BY hostname ASC, CASE assessment WHEN 'weak' THEN 0 WHEN 'unknown' THEN 1 ELSE 2 END, rank ASC
