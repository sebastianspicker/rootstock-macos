import Foundation

extension CollectRunner {
    static let coreArtifactPathGroups: [(names: Set<String>, paths: [String])] = [
        (names: ["tcc"], paths: ["Library/Application Support/com.apple.TCC/TCC.db"]),
        (names: ["quarantine"], paths: ["Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"]),
        (names: ["autostart", "launchagents"], paths: ["Library/LaunchAgents", "Library/LaunchDaemons"]),
        (names: ["btm"], paths: ["private/var/db/com.apple.backgroundtaskmanagement", "var/db/com.apple.backgroundtaskmanagement"]),
        (names: ["wifi"], paths: ["Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist", "Library/Preferences/com.apple.wifi.known-networks.plist", "Library/Preferences/wifi_known_networks.json"]),
        (names: ["configprofiles"], paths: ["Library/ConfigurationProfiles", "Library/Managed Preferences"]),
        (names: ["ssh"], paths: ["Users", "etc/ssh"]),
        (names: ["security_posture"], paths: ["Library/Preferences/security_posture.json"]),
        (names: ["alf", "firewall"], paths: ["Library/Preferences/com.apple.alf.plist"]),
        (names: ["dock"], paths: ["Users"]),
        (names: ["users", "basicinfo"], paths: ["var/db/dslocal/nodes/Default/users"]),
        (names: ["unifiedlog_export", "asl", "installhistory"], paths: ["Library/Logs"]),
        (names: ["xprotect"], paths: ["Library/Logs/DiagnosticReports"]),
        (names: ["safari"], paths: ["Users/alice/Library/Safari", "Users"]),
        (names: ["chromium", "chrome"], paths: ["Users/alice/Library/Application Support/Google/Chrome", "Users"]),
        (names: ["knowledgec", "pol"], paths: ["Users/alice/Library/Application Support/Knowledge", "Users"]),
        (names: ["recentitems", "mru"], paths: ["Users/alice/Library/Application Support/com.apple.sharedfilelist", "Users"]),
        (names: ["firefox", "cookies"], paths: ["Users"]),
        (names: ["loginitems", "login_items"], paths: ["Users/alice/Library/Application Support/com.apple.sharedfilelist", "Users"]),
        (names: ["crons", "cron"], paths: ["etc/crontab", "etc/cron.d", "etc/periodic", "var/at/tabs", "private/var/at/tabs", "Library/Preferences/cron_jobs.json"]),
        (names: ["biome", "pol_biome"], paths: ["Users/alice/Library/Biome", "Users"]),
        (names: ["systemextensions", "sysext"], paths: ["Library/SystemExtensions", "Library/Preferences/system_extensions.json"]),
        (names: ["utmpx", "sessions", "wtmp"], paths: ["private/var/run/utmpx.jsonl", "var/run/utmpx.jsonl", "var/run/utmpx.json", "var/log/wtmp.jsonl", "Library/Logs/utmpx_export.jsonl", "Library/Logs/wtmp_export.jsonl"]),
        (names: ["browser_extensions", "extensions"], paths: ["Users/alice/Library/Application Support/Google/Chrome/Default/extensions.json", "Users/alice/Library/Application Support/Google/Chrome", "Users"]),
        (names: ["gatekeeper", "gk"], paths: ["Library/Logs/Gatekeeper", "Library/Preferences/com.apple.security.gk.json", "Library/Preferences/gatekeeper_assessments.json"]),
        (names: ["netlocation", "network_locations", "network-context"], paths: ["Library/Preferences/SystemConfiguration/network_locations.json", "Library/Preferences/SystemConfiguration/preferences.plist", "Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist"]),
    ]

    static let persistenceArtifactPathGroups: [(names: Set<String>, paths: [String])] = [
        (names: ["shell_profiles", "shellprofiles", "shellrc"], paths: ["Users", "etc/profile", "etc/zprofile", "etc/zshrc", "etc/bashrc", "private/etc/profile"]),
        (names: ["emond"], paths: ["etc/emond.d", "private/etc/emond.d", "Library/Preferences/emond_rules.json"]),
        (names: ["sudoers"], paths: ["etc/sudoers", "etc/sudoers.d", "private/etc/sudoers", "private/etc/sudoers.d"]),
        (names: ["launchd_overrides", "launchdoverrides", "disabled_plist"], paths: ["var/db/com.apple.xpc.launchd", "private/var/db/com.apple.xpc.launchd", "Library/Preferences/launchd_disabled.json"]),
        (names: ["privhelpers", "privileged_helpers", "privilegedhelpers"], paths: ["Library/PrivilegedHelperTools", "Library/Preferences/privileged_helpers.json", "Library/LaunchDaemons"]),
        (names: ["folder_actions", "folderactions", "folder_action"], paths: ["Users", "Library/Scripts", "Library/Preferences/folder_actions.json"]),
        (names: ["login_hooks", "loginhooks", "loginwindow_hooks"], paths: ["Library/Preferences/com.apple.loginwindow.plist", "Library/Preferences/login_hooks.json", "var/root/Library/Preferences/com.apple.loginwindow.plist", "etc/kcpassword"]),
        (names: ["software_update", "softwareupdate"], paths: ["Library/Preferences/com.apple.SoftwareUpdate.plist"]),
        (names: ["file_sharing", "smb"], paths: ["Library/Preferences/SystemConfiguration/com.apple.smb.server.plist", "Library/Preferences/com.apple.AppleFileServer.plist"]),
        (names: ["auth_plugins", "authplugins", "authorization_plugins"], paths: ["Library/Security/SecurityAgentPlugins", "Library/Preferences/auth_plugins.json", "Library/Security/auth_plugins.json"]),
        (names: ["netusage", "net_usage", "network_usage"], paths: ["Library/Preferences/netusage.json", "Library/Preferences/com.apple.networkextension.plist", "Library/Preferences/com.apple.networkusage.plist"]),
        (names: ["usb_history", "usbhistory", "usb"], paths: ["Library/Preferences/usb_history.json", "Library/Preferences/com.apple.usb.plist", "Library/Logs/usb_history.jsonl"]),
        (names: ["keychain_meta", "keychainmeta", "keychain_metadata"], paths: ["Library/Preferences/keychain_metadata.json", "Users", "Library/Keychains/keychain_metadata.json"]),
        (names: ["codesign", "codesign_inventory"], paths: ["Library/Preferences/codesign_inventory.json", "Library/PrivilegedHelperTools", "Library/LaunchDaemons"]),
        (names: ["ard", "remote_management", "remote_desktop"], paths: ["Library/Preferences/com.apple.RemoteManagement.plist", "Library/Preferences/com.apple.RemoteDesktop.plist", "Library/Preferences/ard_inventory.json"]),
        (names: ["spotlight", "spotlight_inventory"], paths: ["Library/Preferences/spotlight_inventory.json", "Library/Preferences/spotlight_export.json", "Library/Logs/spotlight_export.jsonl", "Users"]),
        (names: ["trash", "trash_inventory"], paths: ["Library/Preferences/trash_inventory.json", "Library/Logs/trash_export.jsonl", "Users"]),
        (names: ["doc_revisions", "docrevisions", "document_revisions"], paths: ["Library/Preferences/doc_revisions.json", "Library/Preferences/document_revisions.json", ".DocumentRevisions-V100", "Users"]),
        (names: ["saved_state", "savedstate", "saved_application_state"], paths: ["Library/Preferences/saved_state.json", "Library/Preferences/saved_application_state.json", "Users"]),
    ]

    static let residualArtifactPathGroups: [(names: Set<String>, paths: [String])] = [
        (names: ["notifications", "notification_center"], paths: ["Library/Preferences/notification_center.json", "Library/Preferences/notifications.json", "Library/Logs/notification_center.jsonl", "Users"]),
        (names: ["quicklook", "quicklook_cache"], paths: ["Library/Preferences/quicklook_cache.json", "Library/Logs/quicklook_cache.jsonl", "Users"]),
        (names: ["screentime", "screen_time", "screentime_markers"], paths: ["Library/Preferences/screentime_markers.json", "Library/Preferences/screentime.json", "Library/Preferences/screen_time.json", "Users"]),
        (names: ["icloud", "icloud_account", "icloud_sync"], paths: ["Library/Preferences/icloud_account.json", "Library/Preferences/icloud_sync.json", "Users"]),
        (names: ["forensics_browser"], paths: ["Users/alice/Library/Safari", "Users/alice/Library/Application Support/Google/Chrome", "Users/alice/Library/Application Support/Firefox"]),
        (names: ["forensics_pol"], paths: ["Users/alice/Library/Application Support/Knowledge", "Users/alice/Library/Application Support/com.apple.sharedfilelist", "Users/alice/Library/Biome", "Library/Preferences/screentime_markers.json"]),
    ]
}
