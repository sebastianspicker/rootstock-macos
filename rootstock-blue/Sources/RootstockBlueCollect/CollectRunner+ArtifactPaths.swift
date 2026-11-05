import Foundation

extension CollectRunner {
    /// Collectors must not export passwords, private keys, session tokens or keychain secrets
    /// (docs/THREAT_MODEL.md). Walked folders can hold them, so they are withheld by name.
    static let credentialFileNames: Set<String> = [
        "logins.json", "logins-backup.json", "key3.db", "key4.db", "signons.sqlite",
        "cookies.sqlite", "cookies", "cookies.binarycookies", "login data", "login data for account",
        "web data", "kcpassword", "configprofiles.binary",
    ]
    static let credentialExtensions: Set<String> = ["p12", "pfx", "key", "keychain", "keychain-db"]

    static func isCredentialStore(_ name: String) -> Bool {
        var lower = name.lowercased()
        for suffix in ["-journal", "-wal", "-shm"] where lower.hasSuffix(suffix) {
            lower.removeLast(suffix.count)
        }
        if credentialFileNames.contains(lower) { return true }
        if credentialExtensions.contains((lower as NSString).pathExtension) { return true }
        // SSH private keys: id_ed25519 (not id_ed25519.pub), ssh_host_rsa_key.
        return (lower.hasPrefix("id_") && !lower.hasSuffix(".pub"))
            || (lower.hasPrefix("ssh_host_") && lower.hasSuffix("_key"))
    }

    /// `Users/*/` paths are expanded over the real user folders of the source tree at planning time.
    /// Never list bare `Users`: a folder path is walked, and that would copy whole home folders.
    /// Credential stores inside walked folders are withheld by `CollectRunner.isCredentialStore`.
    static let coreArtifactPathGroups: [(names: Set<String>, paths: [String])] = [
        (names: ["tcc"], paths: ["Library/Application Support/com.apple.TCC/TCC.db"]),
        (names: ["quarantine"], paths: ["Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"]),
        (names: ["autostart", "launchagents"], paths: ["Library/LaunchAgents", "Library/LaunchDaemons"]),
        (names: ["btm"], paths: ["private/var/db/com.apple.backgroundtaskmanagement", "var/db/com.apple.backgroundtaskmanagement"]),
        (names: ["wifi"], paths: ["Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist", "Library/Preferences/com.apple.wifi.known-networks.plist", "Library/Preferences/wifi_known_networks.json"]),
        // Profile payloads and managed preferences can embed Wi-Fi/VPN passwords, identity
        // certificates and MDM enrollment tokens, so this group copies nothing.
        (names: ["configprofiles"], paths: []),
        (names: ["ssh"], paths: ["Users/*/.ssh/authorized_keys", "Users/*/.ssh/authorized_keys2", "Users/*/.ssh/known_hosts", "Users/*/.ssh/config", "etc/ssh/sshd_config", "etc/ssh/sshd_config.d", "etc/ssh/ssh_config", "etc/ssh/ssh_config.d", "private/etc/ssh/sshd_config", "private/etc/ssh/sshd_config.d", "private/etc/ssh/ssh_config", "private/etc/ssh/ssh_config.d"]),
        (names: ["security_posture"], paths: ["Library/Preferences/security_posture.json"]),
        (names: ["alf", "firewall"], paths: ["Library/Preferences/com.apple.alf.plist"]),
        (names: ["dock"], paths: ["Users/*/Library/Preferences/com.apple.dock.plist"]),
        // dslocal user plists hold ShadowHashData (password hashes), so they are never collected.
        (names: ["users", "basicinfo"], paths: []),
        (names: ["unifiedlog_export", "asl", "installhistory"], paths: ["Library/Logs"]),
        (names: ["xprotect"], paths: ["Library/Logs/DiagnosticReports"]),
        (names: ["safari"], paths: ["Users/*/Library/Safari"]),
        (names: ["chromium", "chrome"], paths: ["Users/*/Library/Application Support/Google/Chrome"]),
        (names: ["knowledgec", "pol"], paths: ["Users/*/Library/Application Support/Knowledge"]),
        (names: ["recentitems", "mru"], paths: ["Users/*/Library/Application Support/com.apple.sharedfilelist"]),
        (names: ["firefox", "cookies"], paths: ["Users/*/Library/Application Support/Firefox"]),
        (names: ["loginitems", "login_items"], paths: ["Users/*/Library/Application Support/com.apple.sharedfilelist"]),
        (names: ["crons", "cron"], paths: ["etc/crontab", "etc/cron.d", "etc/periodic", "private/etc/crontab", "private/etc/cron.d", "private/etc/periodic", "var/at/tabs", "private/var/at/tabs", "Library/Preferences/cron_jobs.json"]),
        (names: ["biome", "pol_biome"], paths: ["Users/*/Library/Biome"]),
        (names: ["systemextensions", "sysext"], paths: ["Library/SystemExtensions", "Library/Preferences/system_extensions.json"]),
        (names: ["utmpx", "sessions", "wtmp"], paths: ["private/var/run/utmpx.jsonl", "var/run/utmpx.jsonl", "var/run/utmpx.json", "var/log/wtmp.jsonl", "Library/Logs/utmpx_export.jsonl", "Library/Logs/wtmp_export.jsonl"]),
        (names: ["browser_extensions", "extensions"], paths: ["Users/*/Library/Application Support/Google/Chrome/Default/extensions.json", "Users/*/Library/Application Support/Google/Chrome"]),
        (names: ["gatekeeper", "gk"], paths: ["Library/Logs/Gatekeeper", "Library/Preferences/com.apple.security.gk.json", "Library/Preferences/gatekeeper_assessments.json"]),
        (names: ["netlocation", "network_locations", "network-context"], paths: ["Library/Preferences/SystemConfiguration/network_locations.json", "Library/Preferences/SystemConfiguration/preferences.plist", "Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist"]),
    ]

    static let persistenceArtifactPathGroups: [(names: Set<String>, paths: [String])] = [
        (names: ["shell_profiles", "shellprofiles", "shellrc"], paths: ["Users/*/.zshrc", "Users/*/.zprofile", "Users/*/.bashrc", "Users/*/.bash_profile", "Users/*/.bash_login", "Users/*/.profile", "etc/profile", "etc/zprofile", "etc/zshrc", "etc/bashrc", "private/etc/profile", "private/etc/zprofile", "private/etc/zshrc", "private/etc/bashrc"]),
        (names: ["emond"], paths: ["etc/emond.d", "private/etc/emond.d", "Library/Preferences/emond_rules.json"]),
        (names: ["sudoers"], paths: ["etc/sudoers", "etc/sudoers.d", "private/etc/sudoers", "private/etc/sudoers.d"]),
        (names: ["launchd_overrides", "launchdoverrides", "disabled_plist"], paths: ["var/db/com.apple.xpc.launchd", "private/var/db/com.apple.xpc.launchd", "Library/Preferences/launchd_disabled.json"]),
        (names: ["privhelpers", "privileged_helpers", "privilegedhelpers"], paths: ["Library/PrivilegedHelperTools", "Library/Preferences/privileged_helpers.json", "Library/LaunchDaemons"]),
        (names: ["folder_actions", "folderactions", "folder_action"], paths: ["Users/*/Library/Preferences/com.apple.FolderActionsDispatcher.plist", "Users/*/Library/Workflows/Applications/Folder Actions", "Library/Scripts", "Library/Preferences/folder_actions.json"]),
        (names: ["login_hooks", "loginhooks", "loginwindow_hooks"], paths: ["Library/Preferences/com.apple.loginwindow.plist", "Library/Preferences/login_hooks.json", "var/root/Library/Preferences/com.apple.loginwindow.plist"]),
        (names: ["software_update", "softwareupdate"], paths: ["Library/Preferences/com.apple.SoftwareUpdate.plist"]),
        (names: ["file_sharing", "smb"], paths: ["Library/Preferences/SystemConfiguration/com.apple.smb.server.plist", "Library/Preferences/com.apple.AppleFileServer.plist"]),
        (names: ["auth_plugins", "authplugins", "authorization_plugins"], paths: ["Library/Security/SecurityAgentPlugins", "Library/Preferences/auth_plugins.json", "Library/Security/auth_plugins.json"]),
        (names: ["netusage", "net_usage", "network_usage"], paths: ["Library/Preferences/netusage.json", "Library/Preferences/com.apple.networkextension.plist", "Library/Preferences/com.apple.networkusage.plist"]),
        (names: ["usb_history", "usbhistory", "usb"], paths: ["Library/Preferences/usb_history.json", "Library/Preferences/com.apple.usb.plist", "Library/Logs/usb_history.jsonl"]),
        (names: ["keychain_meta", "keychainmeta", "keychain_metadata"], paths: ["Library/Preferences/keychain_metadata.json", "Library/Keychains/keychain_metadata.json"]),
        (names: ["codesign", "codesign_inventory"], paths: ["Library/Preferences/codesign_inventory.json", "Library/PrivilegedHelperTools", "Library/LaunchDaemons"]),
        (names: ["ard", "remote_management", "remote_desktop"], paths: ["Library/Preferences/com.apple.RemoteManagement.plist", "Library/Preferences/com.apple.RemoteDesktop.plist", "Library/Preferences/ard_inventory.json"]),
        (names: ["spotlight", "spotlight_inventory"], paths: ["Library/Preferences/spotlight_inventory.json", "Library/Preferences/spotlight_export.json", "Library/Logs/spotlight_export.jsonl"]),
        (names: ["trash", "trash_inventory"], paths: ["Library/Preferences/trash_inventory.json", "Library/Logs/trash_export.jsonl"]),
        (names: ["doc_revisions", "docrevisions", "document_revisions"], paths: ["Library/Preferences/doc_revisions.json", "Library/Preferences/document_revisions.json", ".DocumentRevisions-V100"]),
        (names: ["saved_state", "savedstate", "saved_application_state"], paths: ["Library/Preferences/saved_state.json", "Library/Preferences/saved_application_state.json"]),
    ]

    static let residualArtifactPathGroups: [(names: Set<String>, paths: [String])] = [
        (names: ["notifications", "notification_center"], paths: ["Library/Preferences/notification_center.json", "Library/Preferences/notifications.json", "Library/Logs/notification_center.jsonl"]),
        (names: ["quicklook", "quicklook_cache"], paths: ["Library/Preferences/quicklook_cache.json", "Library/Logs/quicklook_cache.jsonl"]),
        (names: ["screentime", "screen_time", "screentime_markers"], paths: ["Library/Preferences/screentime_markers.json", "Library/Preferences/screentime.json", "Library/Preferences/screen_time.json"]),
        (names: ["icloud", "icloud_account", "icloud_sync"], paths: ["Library/Preferences/icloud_account.json", "Library/Preferences/icloud_sync.json"]),
        (names: ["forensics_browser"], paths: ["Users/*/Library/Safari", "Users/*/Library/Application Support/Google/Chrome", "Users/*/Library/Application Support/Firefox"]),
        (names: ["forensics_pol"], paths: ["Users/*/Library/Application Support/Knowledge", "Users/*/Library/Application Support/com.apple.sharedfilelist", "Users/*/Library/Biome", "Library/Preferences/screentime_markers.json"]),
    ]
}
