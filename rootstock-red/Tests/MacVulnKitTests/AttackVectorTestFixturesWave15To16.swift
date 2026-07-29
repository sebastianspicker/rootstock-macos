import XCTest
import RootstockCore
import MacEnumKit
import MacArtifactKit
@testable import MacVulnKit

extension AttackVectorTests {
    static func configureFixtureWave15To16(_ state: inout CollectedState) {
        configureFixtureWave15To16Part1(&state)
        configureFixtureWave15To16Part2(&state)
        configureFixtureWave15To16Part3(&state)
        configureFixtureWave15To16Part4(&state)
        configureFixtureWave15To16Part5(&state)
    }
    static func configureFixtureWave15To16Part1(_ state: inout CollectedState) {
        configureFixtureWave15To16Part1Segment1(&state)
        configureFixtureWave15To16Part1Segment2(&state)
    }

    static func configureFixtureWave15To16Part1Segment1(_ state: inout CollectedState) {
        configureFixtureWave15To16Part1Segment1Leaf1(&state)
        configureFixtureWave15To16Part1Segment1Leaf2(&state)
    }

    static func configureFixtureWave15To16Part1Segment1Leaf1(_ state: inout CollectedState) {



        // Wave-15 multi-plane synthetic surfaces

        state.photosLibraryPath = PhotosLibraryPathState(
            photosAppPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            photosLibraryPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-photos_library_path.plist", "/usr/bin/osascript"],
            photosSupportPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            photosSurfacePresent: true,
            notes: ["synthetic Photos library path plane - never reads photo contents or exports Photo Library media"]
        )
        state.collectorNotes["collect.photos_library_path"] = "a=3 b=2 c=3 surface=true"

        state.vpnConfigDualuse = VpnConfigDualuseState(
            vpnFrameworkPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            vpnPrefPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-vpn_config_dualuse.plist", "/usr/bin/osascript"],
            vpnToolPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            vpnSurfacePresent: true,
            notes: ["synthetic VPN config dual-use - never installs VPN profiles or rewrites network extension VPN configs"]
        )
        state.collectorNotes["collect.vpn_config_dualuse"] = "a=3 b=2 c=3 surface=true"

    }

    static func configureFixtureWave15To16Part1Segment1Leaf2(_ state: inout CollectedState) {
        state.sandboxContainerDepth = SandboxContainerDepthState(
            containerRootPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            sandboxProfilePaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-sandbox_container_depth.plist", "/usr/bin/osascript"],
            seatbeltSupportPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            sandboxSurfacePresent: true,
            notes: ["synthetic Sandbox container depth - never breaks app sandbox or forges container entitlements"]
        )
        state.collectorNotes["collect.sandbox_container_depth"] = "a=3 b=2 c=3 surface=true"

        state.xpcMachServiceDepth = XpcMachServiceDepthState(
            xpcBootstrapPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            machServicePlistPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-xpc_mach_service_depth.plist", "/usr/bin/osascript"],
            xpcToolPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            xpcMachSurfacePresent: true,
            notes: ["synthetic XPC Mach service depth - never registers XPC services or injects into Mach ports"]
        )
        state.collectorNotes["collect.xpc_mach_service_depth"] = "a=3 b=2 c=3 surface=true"

        }

    static func configureFixtureWave15To16Part1Segment2(_ state: inout CollectedState) {
        configureFixtureWave15To16Part1Segment2Leaf1(&state)
        configureFixtureWave15To16Part1Segment2Leaf2(&state)
    }

    static func configureFixtureWave15To16Part1Segment2Leaf1(_ state: inout CollectedState) {

        state.tmLocalSnapshotDepth = TmLocalSnapshotDepthState(
            tmUtilPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            snapshotStorePaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-tm_local_snapshot_depth.plist", "/usr/bin/osascript"],
            tmPrefPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            tmSnapshotSurfacePresent: true,
            notes: ["synthetic TM local snapshot depth - never mounts snapshots for data theft or deletes backup catalogs"]
        )
        state.collectorNotes["collect.tm_local_snapshot_depth"] = "a=3 b=2 c=3 surface=true"

        state.emondLegacyDepth = EmondLegacyDepthState(
            emondBinaryPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            emondRulePaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-emond_legacy_depth.plist", "/usr/bin/osascript"],
            emondSupportPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            emondSurfacePresent: true,
            notes: ["synthetic Emond legacy depth - never installs emond rules or enables the legacy event monitor daemon"]
        )
        state.collectorNotes["collect.emond_legacy_depth"] = "a=3 b=2 c=3 surface=true"

    }

    static func configureFixtureWave15To16Part1Segment2Leaf2(_ state: inout CollectedState) {
        state.screenSharingArdDepth = ScreenSharingArdDepthState(
            screenSharingAppPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            ardAgentPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-screen_sharing_ard_depth.plist", "/usr/bin/osascript"],
            remoteMgmtPrefPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            ardSurfacePresent: true,
            notes: ["synthetic Screen Sharing ARD depth - never enables Screen Sharing or ARD, never connects to remote desktops"]
        )
        state.collectorNotes["collect.screen_sharing_ard_depth"] = "a=3 b=2 c=3 surface=true"

            }

    static func configureFixtureWave15To16Part2(_ state: inout CollectedState) {
        configureFixtureWave15To16Part2Segment1(&state)
        configureFixtureWave15To16Part2Segment2(&state)
    }

    static func configureFixtureWave15To16Part2Segment1(_ state: inout CollectedState) {
        configureFixtureWave15To16Part2Segment1Leaf1(&state)
        configureFixtureWave15To16Part2Segment1Leaf2(&state)
    }

    static func configureFixtureWave15To16Part2Segment1Leaf1(_ state: inout CollectedState) {


        state.keychainAclPath = KeychainAclPathState(
            keychainDbPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            securityToolPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-keychain_acl_path.plist", "/usr/bin/osascript"],
            keychainSupportPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            keychainAclSurfacePresent: true,
            notes: ["synthetic Keychain ACL path plane - never dumps keychain items, passwords, or private keys"]
        )
        state.collectorNotes["collect.keychain_acl_path"] = "a=3 b=2 c=3 surface=true"

        state.pythonRuntimeDualuse = PythonRuntimeDualuseState(
            pythonBinaryPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            sitePackagePaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-python_runtime_dualuse.plist", "/usr/bin/osascript"],
            pythonFrameworkPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            pythonSurfacePresent: true,
            notes: ["synthetic Python runtime dual-use - never executes third-party Python payloads or drops malicious site-packages"]
        )
        state.collectorNotes["collect.python_runtime_dualuse"] = "a=3 b=2 c=3 surface=true"

    }

    static func configureFixtureWave15To16Part2Segment1Leaf2(_ state: inout CollectedState) {
        state.shellPluginManager = ShellPluginManagerState(
            omzPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            pluginDirPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-shell_plugin_manager.plist", "/usr/bin/osascript"],
            shellInitPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            shellPluginSurfacePresent: true,
            notes: ["synthetic Shell plugin manager dual-use - never installs oh-my-zsh plugins or rewrites shell init for persistence"]
        )
        state.collectorNotes["collect.shell_plugin_manager"] = "a=3 b=2 c=3 surface=true"
        // Wave-16 multi-plane synthetic surfaces (25 themes)

        state.airplayReceiverSurface = AirplayReceiverSurfaceState(
            airplayDaemonPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            airplayPrefPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-airplay_receiver_surface.plist", "/usr/bin/osascript"],
            airplayHelperPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            airplaySurfacePresent: true,
            notes: ["synthetic AirPlay receiver dual-use"]
        )
        state.collectorNotes["collect.airplay_receiver_surface"] = "a=3 b=2 c=3 surface=true"

        }

    static func configureFixtureWave15To16Part2Segment2(_ state: inout CollectedState) {
        configureFixtureWave15To16Part2Segment2Leaf1(&state)
        configureFixtureWave15To16Part2Segment2Leaf2(&state)
    }

    static func configureFixtureWave15To16Part2Segment2Leaf1(_ state: inout CollectedState) {

        state.handoffClipboardDepth = HandoffClipboardDepthState(
            handoffFrameworkPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            clipboardPathHits: [NSHomeDirectory() + "/Library/Preferences/synthetic-handoff_clipboard_depth.plist", "/usr/bin/osascript"],
            sharingdPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            handoffSurfacePresent: true,
            notes: ["synthetic Handoff clipboard depth"]
        )
        state.collectorNotes["collect.handoff_clipboard_depth"] = "a=3 b=2 c=3 surface=true"

        state.imessagePathPlane = ImessagePathPlaneState(
            messagesAppPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            messagesDbPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-imessage_path_plane.plist", "/usr/bin/osascript"],
            messagesPrefPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            imessageSurfacePresent: true,
            notes: ["synthetic iMessage path plane"]
        )
        state.collectorNotes["collect.imessage_path_plane"] = "a=3 b=2 c=3 surface=true"

    }

    static func configureFixtureWave15To16Part2Segment2Leaf2(_ state: inout CollectedState) {
        state.facetimeCameraSurface = FacetimeCameraSurfaceState(
            facetimeAppPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            avConferencePaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-facetime_camera_surface.plist", "/usr/bin/osascript"],
            facetimePrefPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            facetimeSurfacePresent: true,
            notes: ["synthetic FaceTime camera dual-use"]
        )
        state.collectorNotes["collect.facetime_camera_surface"] = "a=3 b=2 c=3 surface=true"

        state.finderSyncExtension = FinderSyncExtensionState(
            finderSyncFrameworkPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            appScriptPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-finder_sync_extension.plist", "/usr/bin/osascript"],
            finderPrefPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            finderSyncSurfacePresent: true,
            notes: ["synthetic Finder Sync dual-use"]
        )
            }

    static func configureFixtureWave15To16Part3(_ state: inout CollectedState) {
        configureFixtureWave15To16Part3Segment1(&state)
        configureFixtureWave15To16Part3Segment2(&state)
    }

    static func configureFixtureWave15To16Part3Segment1(_ state: inout CollectedState) {
        configureFixtureWave15To16Part3Segment1Leaf1(&state)
        configureFixtureWave15To16Part3Segment1Leaf2(&state)
    }

    static func configureFixtureWave15To16Part3Segment1Leaf1(_ state: inout CollectedState) {


        state.collectorNotes["collect.finder_sync_extension"] = "a=3 b=2 c=3 surface=true"

        state.fileproviderDomain = FileproviderDomainState(
            fileProviderFrameworkPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            cloudStoragePaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-fileprovider_domain.plist", "/usr/bin/osascript"],
            fileProviderLaunchPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            fileProviderSurfacePresent: true,
            notes: ["synthetic File Provider domain"]
        )
        state.collectorNotes["collect.fileprovider_domain"] = "a=3 b=2 c=3 surface=true"

        state.notificationCenterDepth = NotificationCenterDepthState(
            notificationFrameworkPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            notificationStorePaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-notification_center_depth.plist", "/usr/bin/osascript"],
            notificationPrefPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            notificationSurfacePresent: true,
            notes: ["synthetic Notification Center depth"]
        )
        state.collectorNotes["collect.notification_center_depth"] = "a=3 b=2 c=3 surface=true"

    }

    static func configureFixtureWave15To16Part3Segment1Leaf2(_ state: inout CollectedState) {
        state.siriSuggestionsPlane = SiriSuggestionsPlaneState(
            siriFrameworkPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            suggestionsStorePaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-siri_suggestions_plane.plist", "/usr/bin/osascript"],
            siriPrefPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            siriSurfacePresent: true,
            notes: ["synthetic Siri Suggestions residual"]
        )
        state.collectorNotes["collect.siri_suggestions_plane"] = "a=3 b=2 c=3 surface=true"

        state.spotlightImporterDepth = SpotlightImporterDepthState(
            metadataToolPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            spotlightImporterPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-spotlight_importer_depth.plist", "/usr/bin/osascript"],
            mdsLaunchPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            spotlightImporterSurfacePresent: true,
            notes: ["synthetic Spotlight importer depth"]
        )
        state.collectorNotes["collect.spotlight_importer_depth"] = "a=3 b=2 c=3 surface=true"

        }

    static func configureFixtureWave15To16Part3Segment2(_ state: inout CollectedState) {
        configureFixtureWave15To16Part3Segment2Leaf1(&state)
        configureFixtureWave15To16Part3Segment2Leaf2(&state)
    }

    static func configureFixtureWave15To16Part3Segment2Leaf1(_ state: inout CollectedState) {

        state.contactsPathPlane = ContactsPathPlaneState(
            contactsAppPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            addressBookPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-contacts_path_plane.plist", "/usr/bin/osascript"],
            contactsPrefPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            contactsSurfacePresent: true,
            notes: ["synthetic Contacts path plane"]
        )
        state.collectorNotes["collect.contacts_path_plane"] = "a=3 b=2 c=3 surface=true"

        state.calendarServerPath = CalendarServerPathState(
            caldavFrameworkPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            calendarsStorePaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-calendar_server_path.plist", "/usr/bin/osascript"],
            calendarAgentPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            caldavSurfacePresent: true,
            notes: ["synthetic Calendar CalDAV residual"]
        )
        state.collectorNotes["collect.calendar_server_path"] = "a=3 b=2 c=3 surface=true"

    }

    static func configureFixtureWave15To16Part3Segment2Leaf2(_ state: inout CollectedState) {
        state.remindersCloudPath = RemindersCloudPathState(
            remindersAppPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            remindersStorePaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-reminders_cloud_path.plist", "/usr/bin/osascript"],
            remindersPrefPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            remindersCloudSurfacePresent: true,
            notes: ["synthetic Reminders cloud path"]
        )
        state.collectorNotes["collect.reminders_cloud_path"] = "a=3 b=2 c=3 surface=true"

        state.mapsLocationPath = MapsLocationPathState(
            mapsAppPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            mapsCachePaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-maps_location_path.plist", "/usr/bin/osascript"],
            locationdPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            mapsLocationSurfacePresent: true,
            notes: ["synthetic Maps location residual"]
        )
            }

    static func configureFixtureWave15To16Part4(_ state: inout CollectedState) {
        configureFixtureWave15To16Part4Segment1(&state)
        configureFixtureWave15To16Part4Segment2(&state)
    }

    static func configureFixtureWave15To16Part4Segment1(_ state: inout CollectedState) {
        configureFixtureWave15To16Part4Segment1Leaf1(&state)
        configureFixtureWave15To16Part4Segment1Leaf2(&state)
    }

    static func configureFixtureWave15To16Part4Segment1Leaf1(_ state: inout CollectedState) {


        state.collectorNotes["collect.maps_location_path"] = "a=3 b=2 c=3 surface=true"

        state.weatherWidgetPath = WeatherWidgetPathState(
            weatherAppPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            weatherContainerPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-weather_widget_path.plist", "/usr/bin/osascript"],
            widgetServicePaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            weatherSurfacePresent: true,
            notes: ["synthetic Weather widget residual"]
        )
        state.collectorNotes["collect.weather_widget_path"] = "a=3 b=2 c=3 surface=true"

        state.musicLibraryPath = MusicLibraryPathState(
            musicAppPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            musicLibraryPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-music_library_path.plist", "/usr/bin/osascript"],
            musicPrefPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            musicSurfacePresent: true,
            notes: ["synthetic Music library path"]
        )
        state.collectorNotes["collect.music_library_path"] = "a=3 b=2 c=3 surface=true"

    }

    static func configureFixtureWave15To16Part4Segment1Leaf2(_ state: inout CollectedState) {
        state.booksPathPlane = BooksPathPlaneState(
            booksAppPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            booksContainerPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-books_path_plane.plist", "/usr/bin/osascript"],
            booksPrefPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            booksSurfacePresent: true,
            notes: ["synthetic Books path plane"]
        )
        state.collectorNotes["collect.books_path_plane"] = "a=3 b=2 c=3 surface=true"

        state.podcastsPathPlane = PodcastsPathPlaneState(
            podcastsAppPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            podcastsStorePaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-podcasts_path_plane.plist", "/usr/bin/osascript"],
            podcastsPrefPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            podcastsSurfacePresent: true,
            notes: ["synthetic Podcasts path plane"]
        )
        state.collectorNotes["collect.podcasts_path_plane"] = "a=3 b=2 c=3 surface=true"

        }

    static func configureFixtureWave15To16Part4Segment2(_ state: inout CollectedState) {
        configureFixtureWave15To16Part4Segment2Leaf1(&state)
        configureFixtureWave15To16Part4Segment2Leaf2(&state)
    }

    static func configureFixtureWave15To16Part4Segment2Leaf1(_ state: inout CollectedState) {

        state.tvAppPathPlane = TvAppPathPlaneState(
            tvAppPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            tvContainerPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-tv_app_path_plane.plist", "/usr/bin/osascript"],
            tvPrefPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            tvSurfacePresent: true,
            notes: ["synthetic TV.app path plane"]
        )
        state.collectorNotes["collect.tv_app_path_plane"] = "a=3 b=2 c=3 surface=true"

        state.homekitPathPlane = HomekitPathPlaneState(
            homeAppPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            homeKitStorePaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-homekit_path_plane.plist", "/usr/bin/osascript"],
            homedPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            homekitSurfacePresent: true,
            notes: ["synthetic HomeKit path plane"]
        )
        state.collectorNotes["collect.homekit_path_plane"] = "a=3 b=2 c=3 surface=true"

    }

    static func configureFixtureWave15To16Part4Segment2Leaf2(_ state: inout CollectedState) {
        state.healthPathPlane = HealthPathPlaneState(
            healthAppPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            healthStorePaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-health_path_plane.plist", "/usr/bin/osascript"],
            healthdPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            healthSurfacePresent: true,
            notes: ["synthetic Health path plane"]
        )
        state.collectorNotes["collect.health_path_plane"] = "a=3 b=2 c=3 surface=true"

        state.walletPassPath = WalletPassPathState(
            walletAppPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            passesStorePaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-wallet_pass_path.plist", "/usr/bin/osascript"],
            passdPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            walletSurfacePresent: true,
            notes: ["synthetic Wallet pass path"]
        )
            }

    static func configureFixtureWave15To16Part5(_ state: inout CollectedState) {
        configureFixtureWave15To16Part5Segment1(&state)
        configureFixtureWave15To16Part5Segment2(&state)
    }

    static func configureFixtureWave15To16Part5Segment1(_ state: inout CollectedState) {
        configureFixtureWave15To16Part5Segment1Leaf1(&state)
        configureFixtureWave15To16Part5Segment1Leaf2(&state)
    }

    static func configureFixtureWave15To16Part5Segment1Leaf1(_ state: inout CollectedState) {


        state.collectorNotes["collect.wallet_pass_path"] = "a=3 b=2 c=3 surface=true"

        state.findmyPathPlane = FindmyPathPlaneState(
            findMyAppPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            findMyCachePaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-findmy_path_plane.plist", "/usr/bin/osascript"],
            fmfdPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            findmySurfacePresent: true,
            notes: ["synthetic Find My path plane"]
        )
        state.collectorNotes["collect.findmy_path_plane"] = "a=3 b=2 c=3 surface=true"

        state.shortcutsIcloudSync = ShortcutsIcloudSyncState(
            shortcutsAppPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            shortcutsDbPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-shortcuts_icloud_sync.plist", "/usr/bin/osascript"],
            shortcutsPrefPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            shortcutsIcloudSurfacePresent: true,
            notes: ["synthetic Shortcuts iCloud sync"]
        )
        state.collectorNotes["collect.shortcuts_icloud_sync"] = "a=3 b=2 c=3 surface=true"

    }

    static func configureFixtureWave15To16Part5Segment1Leaf2(_ state: inout CollectedState) {
        state.devicemanagementProfile = DevicemanagementProfileState(
            profilesToolPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            managedPrefPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-devicemanagement_profile.plist", "/usr/bin/osascript"],
            mdmClientPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            deviceMgmtSurfacePresent: true,
            notes: ["synthetic Device management profile"]
        )
        state.collectorNotes["collect.devicemanagement_profile"] = "a=3 b=2 c=3 surface=true"

        state.softwareupdateCatalog = SoftwareupdateCatalogState(
            softwareUpdateToolPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            softwareUpdatePrefPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-softwareupdate_catalog.plist", "/usr/bin/osascript"],
            softwareUpdateDaemonPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            softwareUpdateSurfacePresent: true,
            notes: ["synthetic Software Update catalog"]
        )
        }

    static func configureFixtureWave15To16Part5Segment2(_ state: inout CollectedState) {
        state.collectorNotes["collect.softwareupdate_catalog"] = "a=3 b=2 c=3 surface=true"




            }


    static func configureFixtureAmplifiers(_ state: inout CollectedState) {
        // Amplifiers for Wave-11 compounds
        if state.network == nil {
            state.network = NetworkState(reachability: .init(remoteLoginSSH: true, screenSharingARD: true))
        } else {
            state.network?.remoteLoginSSH = true
            state.network?.screenSharingARD = true
        }
        if state.tcc == nil {
            state.tcc = TCCState(fullDiskAccessLikely: true, notes: ["wave11"], probeMethod: "synthetic")
        } else {
            state.tcc?.fullDiskAccessLikely = true
        }
        if state.remoteAppleEvents == nil {
            state.remoteAppleEvents = RemoteAppleEventsState(
                remoteAEPrefPaths: ["/Library/Preferences/com.apple.RemoteManagement.plist"],
                eppcFrameworkPaths: ["/System/Library/Frameworks/CoreServices.framework"],
                remoteMgmtHints: ["synthetic RAE"],
                remoteAutomationSurfacePresent: true,
                notes: ["synthetic RAE for wave11"]
            )
        }
        if state.esf == nil {
            state.esf = ESFPostureState(clientPaths: [], notes: ["synthetic empty ES clients"])
        }
    }}
