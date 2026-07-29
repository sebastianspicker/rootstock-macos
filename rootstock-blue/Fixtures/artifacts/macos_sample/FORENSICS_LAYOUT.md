# Post-incident fixture layout

| Path | Source | Parser |
|------|--------|--------|
| Users/alice/Library/Safari/History.db | Safari visits | SAFARI |
| Users/alice/Library/Safari/Downloads.plist | Safari downloads | SAFARI |
| Users/.../Google/Chrome/Default/History | Chromium | CHROMIUM |
| Users/.../Google/Chrome/Default/extensions.json | Browser extensions | BROWSER_EXTENSIONS |
| Users/.../Knowledge/knowledgeC.db | Synthetic PoL | KNOWLEDGEC |
| Users/.../Biome/streams.json | Biome PoL streams | BIOME |
| Users/.../com.apple.sharedfilelist/RecentDocuments.plist | Recent MRU | RECENTITEMS |
| Users/.../com.apple.sharedfilelist/com.apple.LSSharedFileList.LoginItems.json | Login Items | LOGINITEMS |
| System/Library/CoreServices/SystemVersion.plist | Host OS version | BASICINFO |
| Library/Preferences/SystemConfiguration/preferences.plist | ComputerName / HostName | BASICINFO |
| Library/Preferences/SystemConfiguration/network_locations.json | Network locations | NETLOCATION |
| Library/Receipts/InstallHistory.plist | Software installs | INSTALLHISTORY |
| Users/alice/Library/Preferences/com.apple.dock.plist | Dock apps / recent | DOCK |
| Library/CS/falconctl, Applications/Santa.app | Security product markers | IRPOSTURE (offline) |
| Library/Preferences/security_posture.json | Offline IR posture JSON | IRPOSTURE |
| Library/Preferences/com.apple.alf.plist | Application firewall | IRPOSTURE |
| private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v13.btm.json | BTM login/background items | BTM |
| Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist | Preferred Wi-Fi networks | WIFI |
| Library/ConfigurationProfiles/payloads/com.evil.mdm.shell.plist | MDM / config profile payload | CONFIGPROFILES |
| Users/alice/.ssh/authorized_keys | SSH authorized public keys | SSH |
| Users/alice/.ssh/known_hosts | SSH known hosts | SSH |
| etc/ssh/sshd_config | sshd auth posture directives | SSH |
| etc/crontab, etc/cron.d/*, var/at/tabs/*, etc/periodic/** | Cron / at / periodic | CRON |
| Library/SystemExtensions/extensions.json | System Extensions inventory | SYSTEMEXTENSIONS |
| private/var/run/utmpx.jsonl, Library/Logs/utmpx_export.jsonl | Login sessions | UTMPX |
| Library/Logs/Gatekeeper/assessments.jsonl | Gatekeeper assessments | GATEKEEPER |
| Library/LaunchAgents, Library/LaunchDaemons | Classic launchd | AUTOSTART |
| Users/alice/.zshrc, etc/zprofile | Shell init profiles | SHELLPROFILES |
| etc/emond.d/rules.json, etc/emond.d/rules/* | Emond rules | EMOND |
| etc/sudoers, etc/sudoers.d/* | sudoers privilege policy | SUDOERS |
| var/db/com.apple.xpc.launchd/disabled.json, private/.../disabled.plist | launchd disabled overrides | LAUNCHDOVERRIDES |
| Library/PrivilegedHelperTools/*, helpers.json, LaunchDaemons/helper | SMJobBless privileged helpers | PRIVHELPERS |
| Users/*/Library/Scripts/Folder Action Scripts, Workflows/folder_actions.json | Folder Actions / Automator | FOLDERACTIONS |
| Library/Preferences/com.apple.loginwindow.plist, login_hooks.json | LoginHook/LogoutHook | LOGINHOOKS |
| etc/kcpassword (presence only) | Auto-login credential marker | IRPOSTURE / harden auto_login |
| Library/Preferences/SystemConfiguration/com.apple.smb.server.plist | File Sharing (SMB) | IRPOSTURE / harden file_sharing |
| Library/Preferences/com.apple.SoftwareUpdate.plist | Update catalog / auto-check | IRPOSTURE / harden software_update_* |
| Users/*/Library/Preferences/.GlobalPreferences.plist (LDMGlobalEnabled) | Lockdown Mode marker | IRPOSTURE / harden lockdown_mode |
| Library/Security/SecurityAgentPlugins/*, auth_plugins.json | Authorization / SecurityAgent plugins | AUTHPLUGINS |
| Library/Preferences/com.apple.networkextension.plist-ish, netusage.json | Process network usage inventory | NETUSAGE |
| Library/Preferences/usb_history.json, IORegistry USB export | USB device connection history | USBHISTORY |
| keychain_metadata.json (class/label/access_group/mtime ONLY) | Keychain metadata anomalies (no secrets) | KEYCHAINMETA |
| codesign_inventory.json | Signing/notarization of persistence binaries | CODESIGN |
| Library/Preferences/com.apple.RemoteManagement.plist, ard_inventory.json | ARD / Remote Management (AllLocalUsers, allow lists) | ARD |

| Library/Preferences/spotlight_inventory.json | Spotlight metadata inventory | SPOTLIGHT |
| `Library/Preferences/trash_inventory.json`, `Users/*/.Trash/*` | Trash recovery inventory | TRASH |
| Library/Preferences/doc_revisions.json, .DocumentRevisions-V100 | DocumentRevisions / Versions markers | DOCREVISIONS |
| Library/Preferences/saved_state.json, Users/*/Library/Saved Application State | Saved Application State | SAVEDSTATE |
| Users/*/Library/Application Support/Firefox/Profiles/*/firefox_history.json | Firefox visits + downloads | FIREFOX |
| Library/Preferences/notification_center.json | Notification Center metadata (no body dump) | NOTIFICATIONS |
| Library/Preferences/quicklook_cache.json | QuickLook thumbnail cache inventory | QUICKLOOK |
| Library/Preferences/screentime_markers.json | Screen Time / Focus markers | SCREENTIME |
| Library/Preferences/icloud_account.json | iCloud account/sync posture | ICLOUD |
| Library/Preferences/cookies_inventory.json | Browser cookie domain inventory (no raw values) | COOKIES |
| Library/Preferences/bookmarks_inventory.json | Browser bookmarks inventory | BOOKMARKS |
| Library/Preferences/office_mru.json | Office/Teams/Slack collaboration MRU | OFFICEMRU |
| Library/Preferences/print_jobs.json | CUPS print job history | PRINTJOBS |
| Library/Preferences/notes_metadata.json | Apple Notes metadata markers (no body) | NOTES |
| Library/Preferences/idevice_backups.json | iDevice backup encrypt posture markers | IDEVICEBACKUP |
| Library/Preferences/msrdc_connections.json | MSRDC/RDP client connection history | MSRDC |
| Library/Preferences/cloud_sync.json | Multi-provider cloud sync (Dropbox/OneDrive/GDrive/Box) | CLOUDSYNC |

Epochs: Safari/knowledgeC = Mac absolute (s since 2001); Chrome = µs since 1601.

IR loop on this tree:
```text
rootstock-blue case create /tmp/demo.rsbcase
rootstock-blue ir triage --case /tmp/demo.rsbcase --source Fixtures/artifacts/macos_sample --offline
# also: ir harden --case … --source …   (structured findings + remediation)
```
