import XCTest
import RootstockCore
import MacEnumKit
import MacArtifactKit
@testable import MacVulnKit

extension AttackVectorTests {
    static func configureFixtureWave9To11(_ state: inout CollectedState) {
        configureFixtureWave9To11Part1(&state)
        configureFixtureWave9To11Part2(&state)
        configureFixtureWave9To11Part3(&state)
    }
    static func configureFixtureWave9To11Part1(_ state: inout CollectedState) {
        configureFixtureWave9To11Part1Segment1(&state)
        configureFixtureWave9To11Part1Segment2(&state)
    }

    static func configureFixtureWave9To11Part1Segment1(_ state: inout CollectedState) {
        configureFixtureWave9To11Part1Segment1Leaf1(&state)
        configureFixtureWave9To11Part1Segment1Leaf2(&state)
    }

    static func configureFixtureWave9To11Part1Segment1Leaf1(_ state: inout CollectedState) {



        state.packageKitInstallerDesign = PackageKitInstallerDesignState(
            installerServicePaths: [
                "/System/Library/PrivateFrameworks/PackageKit.framework/Versions/A/XPCServices/package_script_service.xpc",
                "/usr/libexec/installd",
            ],
            receiptAndHistoryPaths: [
                "/Library/Receipts",
                "/var/db/receipts",
                "/Library/InstallerSandboxes",
            ],
            installerPluginPaths: ["/Library/Installer Plugins"],
            toolingPaths: [
                "/usr/sbin/installer",
                "/usr/sbin/pkgutil",
                "/System/Library/PrivateFrameworks/PackageKit.framework",
            ],
            designSurfacePresent: true,
            notes: ["synthetic PackageKit installer design surface - never builds pkgs"]
        )
    }

    static func configureFixtureWave9To11Part1Segment1Leaf2(_ state: inout CollectedState) {
        state.archiveQuarantineExtractor = ArchiveQuarantineExtractorState(
            thirdPartyExtractorPaths: [
                "/Applications/The Unarchiver.app",
                "/Applications/Keka.app",
            ],
            stockExtractorPaths: [
                "/usr/bin/ditto",
                "/usr/bin/tar",
                "/usr/bin/unzip",
            ],
            archiveDropHints: [NSHomeDirectory() + "/Downloads"],
            extractorSurfacePresent: true,
            notes: ["synthetic archive extractor surface - never strips quarantine"]
        )
        }

    static func configureFixtureWave9To11Part1Segment2(_ state: inout CollectedState) {
        configureFixtureWave9To11Part1Segment2Leaf1(&state)
        configureFixtureWave9To11Part1Segment2Leaf2(&state)
    }

    static func configureFixtureWave9To11Part1Segment2Leaf1(_ state: inout CollectedState) {

        state.infoStealerPathPlane = InfoStealerPathPlaneState(
            browserAdjacentPaths: [
                NSHomeDirectory() + "/Library/Application Support/Google/Chrome",
                NSHomeDirectory() + "/Library/Safari",
            ],
            messagingAndVaultPaths: [
                NSHomeDirectory() + "/Library/Messages",
                NSHomeDirectory() + "/Library/Mail",
                NSHomeDirectory() + "/Library/Keychains",
                NSHomeDirectory() + "/Library/Application Support/1Password",
            ],
            walletAndSyncPaths: [
                NSHomeDirectory() + "/Desktop",
                NSHomeDirectory() + "/Documents",
                NSHomeDirectory() + "/Library/CloudStorage",
            ],
            collectionSurfacePresent: true,
            notes: ["synthetic info-stealer path plane - never dumps secrets"]
        )
    }

    static func configureFixtureWave9To11Part1Segment2Leaf2(_ state: inout CollectedState) {
        state.tccEsfVisibilityDepth = TCCESFVisibilityDepthState(
            tccDbPathHits: [
                NSHomeDirectory() + "/Library/Application Support/com.apple.TCC/TCC.db",
            ],
            visibilityToolPaths: ["/usr/bin/log", "/usr/bin/sqlite3"],
            privacyPrefPaths: ["/Library/Preferences/com.apple.security.plist"],
            visibilityDepth: "partial",
            visibilitySurfacePresent: true,
            notes: ["synthetic TCC/ESF visibility depth - never dumps TCC.db rows"]
        )
            }

    static func configureFixtureWave9To11Part2(_ state: inout CollectedState) {
        configureFixtureWave9To11Part2Segment1(&state)
        configureFixtureWave9To11Part2Segment2(&state)
    }

    static func configureFixtureWave9To11Part2Segment1(_ state: inout CollectedState) {
        configureFixtureWave9To11Part2Segment1Leaf1(&state)
        configureFixtureWave9To11Part2Segment1Leaf2(&state)
    }

    static func configureFixtureWave9To11Part2Segment1Leaf1(_ state: inout CollectedState) {


        state.mdmProfileParseDepth = MDMProfileParseDepthState(
            examinedProfilePaths: [
                NSHomeDirectory() + "/Downloads/synthetic-vpn.mobileconfig",
            ],
            payloadTypes: [
                "Configuration",
                "com.apple.vpn.managed",
                "com.apple.wifi.managed",
            ],
            parsedProfileCount: 1,
            displayNamePresent: true,
            parseSurfacePresent: true,
            notes: ["synthetic MDM profile parse depth - never dumps secrets"]
        )
        state.collectorNotes["collect.packagekit_installer_design"] = "services=2 receipts=3 surface=true"
        state.collectorNotes["collect.archive_quarantine_extractor"] = "thirdParty=2 stock=3 surface=true"
        state.collectorNotes["collect.infostealer_path_plane"] = "browser=2 messagingVault=4 surface=true"
        state.collectorNotes["collect.tcc_esf_visibility_depth"] = "depth=partial surface=true"
        state.collectorNotes["collect.mdm_profile_parse_depth"] = "parsed=1 types=3 surface=true"
    }

    static func configureFixtureWave9To11Part2Segment1Leaf2(_ state: inout CollectedState) {
        state.urlSchemeHandler = URLSchemeHandlerState(
            launchServicesPaths: [
                NSHomeDirectory() + "/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist",
                "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework",
            ],
            urlTypePlistPaths: [
                "/Applications/Safari.app/Contents/Info.plist",
                "/System/Applications/Utilities/Terminal.app/Contents/Info.plist",
            ],
            documentHandlerPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework"],
            openerBinaryPaths: ["/usr/bin/open", "/usr/bin/osascript", "/usr/bin/osacompile"],
            handlerSurfacePresent: true,
            notes: ["synthetic URL scheme handler surface - never registers schemes"]
        )
        }

    static func configureFixtureWave9To11Part2Segment2(_ state: inout CollectedState) {
        configureFixtureWave9To11Part2Segment2Leaf1(&state)
        configureFixtureWave9To11Part2Segment2Leaf2(&state)
    }

    static func configureFixtureWave9To11Part2Segment2Leaf1(_ state: inout CollectedState) {

        state.launchdOverrideDepth = LaunchdOverrideDepthState(
            overridePlistPaths: [
                "/var/db/com.apple.xpc.launchd/disabled.plist",
                "/var/db/launchd.db/com.apple.launchd/overrides.plist",
            ],
            securityDisabledHints: [
                "com.google.santa @ /var/db/com.apple.xpc.launchd/disabled.plist",
                "com.crowdstrike.falcon @ /var/db/com.apple.xpc.launchd/disabled.plist",
            ],
            keepaliveAdjacentPaths: ["/Library/LaunchDaemons", "/Library/LaunchAgents"],
            overrideSurfacePresent: true,
            notes: ["synthetic launchd override depth - never disables jobs"]
        )
    }

    static func configureFixtureWave9To11Part2Segment2Leaf2(_ state: inout CollectedState) {
        state.browserExtensionDualUse = BrowserExtensionDualUseState(
            chromiumExtensionPaths: [
                NSHomeDirectory() + "/Library/Application Support/Google/Chrome/Default/Extensions",
                NSHomeDirectory() + "/Library/Application Support/Microsoft Edge/Default/Extensions",
            ],
            safariExtensionPaths: [
                NSHomeDirectory() + "/Library/Safari/Extensions",
            ],
            preferencePaths: [
                NSHomeDirectory() + "/Library/Application Support/Google/Chrome/Default/Preferences",
                NSHomeDirectory() + "/Library/Preferences/com.apple.Safari.Extensions.plist",
            ],
            extensionSurfacePresent: true,
            notes: ["synthetic browser extension dual-use - never dumps secrets"]
        )
            }

    static func configureFixtureWave9To11Part3(_ state: inout CollectedState) {
        state.shortcutsAppIntents = ShortcutsAppIntentsState(
            shortcutsAppPaths: [
                "/System/Applications/Shortcuts.app",
                NSHomeDirectory() + "/Library/Shortcuts",
                NSHomeDirectory() + "/Library/Group Containers/group.is.workflow.my.app",
            ],
            appIntentsPaths: [
                "/System/Library/Frameworks/AppIntents.framework",
                "/System/Library/PrivateFrameworks/WorkflowKit.framework",
            ],
            automationPrefPaths: [
                NSHomeDirectory() + "/Library/Preferences/com.apple.shortcuts.plist",
            ],
            automationSurfacePresent: true,
            notes: ["synthetic Shortcuts/App Intents surface - never runs shortcuts"]
        )
        state.collectorNotes["collect.url_scheme_handler"] = "ls=2 urlTypes=2 openers=3 surface=true"
        state.collectorNotes["collect.launchd_override_depth"] = "overrides=2 securityHints=2 surface=true"
        state.collectorNotes["collect.browser_extension_dualuse"] = "chromium=2 safari=1 surface=true"
        state.collectorNotes["collect.shortcuts_app_intents"] = "shortcuts=3 intents=2 surface=true"
        }


    static func configureFixtureWave12To14(_ state: inout CollectedState) {
        configureFixtureWave12To14Part1(&state)
        configureFixtureWave12To14Part2(&state)
        configureFixtureWave12To14Part3(&state)
    }
    static func configureFixtureWave12To14Part1(_ state: inout CollectedState) {
        configureFixtureWave12To14Part1Segment1(&state)
        configureFixtureWave12To14Part1Segment2(&state)
    }

    static func configureFixtureWave12To14Part1Segment1(_ state: inout CollectedState) {
        configureFixtureWave12To14Part1Segment1Leaf1(&state)
        configureFixtureWave12To14Part1Segment1Leaf2(&state)
    }

    static func configureFixtureWave12To14Part1Segment1Leaf1(_ state: inout CollectedState) {



        // Wave-12 multi-plane synthetic surfaces

        state.weblocInetlocDelivery = WeblocInetlocDeliveryState(
            weblocSamplePaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            inetlocSamplePaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-webloc_inetloc.plist", "/usr/bin/osascript"],
            dropFolderHints: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            deliverySurfacePresent: true,
            notes: ["synthetic Webloc/inetloc delivery - never crafts phishing webloc/inetloc payloads or rewrites Internet Location files"]
        )
        state.collectorNotes["collect.webloc_inetloc_delivery"] = "a=3 b=2 c=3 surface=true"

        state.mailRulesAutomation = MailRulesAutomationState(
            mailAppPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            rulesPlistPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-mail_rules.plist", "/usr/bin/osascript"],
            scriptingAdjacentPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            rulesSurfacePresent: true,
            notes: ["synthetic Mail rules automation - never reads Mail contents or modifies user Mail rules"]
        )
        state.collectorNotes["collect.mail_rules_automation"] = "a=3 b=2 c=3 surface=true"

    }

    static func configureFixtureWave12To14Part1Segment1Leaf2(_ state: inout CollectedState) {
        state.unifiedLogObservation = UnifiedLogObservationState(
            logToolPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            logarchiveHints: [NSHomeDirectory() + "/Library/Preferences/synthetic-unified_log.plist", "/usr/bin/osascript"],
            privacyPrefPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            observationSurfacePresent: true,
            notes: ["synthetic Unified log observation - never dumps private unified-log message bodies or force-collects other users' logarchives"]
        )
        state.collectorNotes["collect.unified_log_observation"] = "a=3 b=2 c=3 surface=true"

        state.dockPersistenceSurface = DockPersistenceSurfaceState(
            dockPlistPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            recentItemsPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-dock_persist.plist", "/usr/bin/osascript"],
            dockDbHints: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            dockSurfacePresent: true,
            notes: ["synthetic Dock persistence dual-use - never modifies Dock.plist or plants malicious Dock entries"]
        )
        state.collectorNotes["collect.dock_persistence_surface"] = "a=3 b=2 c=3 surface=true"

        }

    static func configureFixtureWave12To14Part1Segment2(_ state: inout CollectedState) {
        configureFixtureWave12To14Part1Segment2Leaf1(&state)
        configureFixtureWave12To14Part1Segment2Leaf2(&state)
    }

    static func configureFixtureWave12To14Part1Segment2Leaf1(_ state: inout CollectedState) {

        state.osascriptScptDelivery = OsascriptScptDeliveryState(
            osaToolPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            scriptEditorPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-osascript_scpt.plist", "/usr/bin/osascript"],
            scptDropHints: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            scptSurfacePresent: true,
            notes: ["synthetic OSA/scpt delivery - never compiles malicious .scpt payloads or executes third-party AppleScripts"]
        )
        state.collectorNotes["collect.osascript_scpt_delivery"] = "a=3 b=2 c=3 surface=true"

        state.networkShareMount = NetworkShareMountState(
            smbClientPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            netAuthPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-network_share.plist", "/usr/bin/osascript"],
            mountPointHints: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            shareSurfacePresent: true,
            notes: ["synthetic Network share mount - never mounts attacker shares or writes credentials to NetAuth"]
        )
        state.collectorNotes["collect.network_share_mount"] = "a=3 b=2 c=3 surface=true"
        // Wave-13 multi-plane synthetic surfaces

    }

    static func configureFixtureWave12To14Part1Segment2Leaf2(_ state: inout CollectedState) {
        state.calendarRemindersAutomation = CalendarRemindersAutomationState(
            calendarAppPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            remindersPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-calendar_reminders.plist", "/usr/bin/osascript"],
            eventKitPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            automationSurfacePresent: true,
            notes: ["synthetic Calendar/Reminders automation - never reads event contents or creates malicious calendar invites"]
        )
        state.collectorNotes["collect.calendar_reminders_automation"] = "a=3 b=2 c=3 surface=true"

            }

    static func configureFixtureWave12To14Part2(_ state: inout CollectedState) {
        configureFixtureWave12To14Part2Segment1(&state)
        configureFixtureWave12To14Part2Segment2(&state)
    }

    static func configureFixtureWave12To14Part2Segment1(_ state: inout CollectedState) {
        configureFixtureWave12To14Part2Segment1Leaf1(&state)
        configureFixtureWave12To14Part2Segment1Leaf2(&state)
    }

    static func configureFixtureWave12To14Part2Segment1Leaf1(_ state: inout CollectedState) {


        state.gatekeeperAssessmentHistory = GatekeeperAssessmentHistoryState(
            syspolicydPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            assessmentDbPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-gk_assessment.plist", "/usr/bin/osascript"],
            spctlToolPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            assessmentSurfacePresent: true,
            notes: ["synthetic Gatekeeper assessment history - never clears Gatekeeper assessments or disables syspolicyd"]
        )
        state.collectorNotes["collect.gatekeeper_assessment_history"] = "a=3 b=2 c=3 surface=true"

        state.homebrewPackageDualUse = HomebrewPackageDualUseState(
            brewBinaryPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            cellarPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-homebrew_pkg.plist", "/usr/bin/osascript"],
            tapPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            packageSurfacePresent: true,
            notes: ["synthetic Homebrew package dual-use - never installs packages or modifies Homebrew formulae"]
        )
        state.collectorNotes["collect.homebrew_package_dualuse"] = "a=3 b=2 c=3 surface=true"

    }

    static func configureFixtureWave12To14Part2Segment1Leaf2(_ state: inout CollectedState) {
        state.cupsPrintDualUse = CupsPrintDualUseState(
            cupsDaemonPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            ppdConfigPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-cups_print.plist", "/usr/bin/osascript"],
            printToolPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            printSurfacePresent: true,
            notes: ["synthetic CUPS printer dual-use - never submits print jobs or reconfigures CUPS remotely"]
        )
        state.collectorNotes["collect.cups_print_dualuse"] = "a=3 b=2 c=3 surface=true"

        state.screenCapturePrivacyDualUse = ScreenCapturePrivacyDualUseState(
            screencaptureToolPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            screenCaptureKitPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-screencapture.plist", "/usr/bin/osascript"],
            screenshotDropHints: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            captureSurfacePresent: true,
            notes: ["synthetic ScreenCapture privacy dual-use - never captures screens or dumps Screen Recording TCC rows"]
        )
        state.collectorNotes["collect.screencapture_privacy_dualuse"] = "a=3 b=2 c=3 surface=true"
        // Wave-14 multi-plane synthetic surfaces

        }

    static func configureFixtureWave12To14Part2Segment2(_ state: inout CollectedState) {
        configureFixtureWave12To14Part2Segment2Leaf1(&state)
        configureFixtureWave12To14Part2Segment2Leaf2(&state)
    }

    static func configureFixtureWave12To14Part2Segment2Leaf1(_ state: inout CollectedState) {

        state.automatorWorkflow = AutomatorWorkflowState(
            automatorAppPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            workflowSamplePaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-automator_workflow.plist", "/usr/bin/osascript"],
            actionLibraryPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            workflowSurfacePresent: true,
            notes: ["synthetic Automator workflow delivery - never executes Automator workflows or plants malicious .workflow bundles"]
        )
        state.collectorNotes["collect.automator_workflow"] = "a=3 b=2 c=3 surface=true"

        state.icloudDrivePath = IcloudDrivePathState(
            mobileDocumentsPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            icloudDrivePaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-icloud_drive_path.plist", "/usr/bin/osascript"],
            cloudKitPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            icloudPathSurfacePresent: true,
            notes: ["synthetic iCloud Drive path plane - never enumerates iCloud file contents or exfiltrates Mobile Documents"]
        )
        state.collectorNotes["collect.icloud_drive_path"] = "a=3 b=2 c=3 surface=true"

    }

    static func configureFixtureWave12To14Part2Segment2Leaf2(_ state: inout CollectedState) {
        state.bluetoothContinuityDepth = BluetoothContinuityDepthState(
            bluetoothDaemonPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            continuitySupportPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-bluetooth_continuity_depth.plist", "/usr/bin/osascript"],
            btPreferencePaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            btContinuitySurfacePresent: true,
            notes: ["synthetic Bluetooth Continuity depth - never enables Bluetooth pairing or spoofs Continuity identities"]
        )
        state.collectorNotes["collect.bluetooth_continuity_depth"] = "a=3 b=2 c=3 surface=true"

        state.fontValidationDualuse = FontValidationDualuseState(
            fontToolPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            atsSupportPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-font_validation_dualuse.plist", "/usr/bin/osascript"],
            userFontPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            fontSurfacePresent: true,
            notes: ["synthetic Font validation dual-use - never installs malicious fonts or disables font validation"]
        )
            }

    static func configureFixtureWave12To14Part3(_ state: inout CollectedState) {
        configureFixtureWave12To14Part3Segment1(&state)
        configureFixtureWave12To14Part3Segment2(&state)
    }

    static func configureFixtureWave12To14Part3Segment1(_ state: inout CollectedState) {
        configureFixtureWave12To14Part3Segment1Leaf1(&state)
        configureFixtureWave12To14Part3Segment1Leaf2(&state)
    }

    static func configureFixtureWave12To14Part3Segment1Leaf1(_ state: inout CollectedState) {


        state.collectorNotes["collect.font_validation_dualuse"] = "a=3 b=2 c=3 surface=true"

        state.quicklookCacheDepth = QuicklookCacheDepthState(
            quicklookDaemonPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            thumbnailCachePaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-quicklook_cache_depth.plist", "/usr/bin/osascript"],
            qlmanagePaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            quicklookSurfacePresent: true,
            notes: ["synthetic QuickLook cache depth - never dumps QuickLook thumbnail bitmap contents as secret material"]
        )
        state.collectorNotes["collect.quicklook_cache_depth"] = "a=3 b=2 c=3 surface=true"

        state.dnsResolverDualuse = DnsResolverDualuseState(
            mdnsResponderPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            resolverConfigPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-dns_resolver_dualuse.plist", "/usr/bin/osascript"],
            dnsToolPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            dnsSurfacePresent: true,
            notes: ["synthetic DNS resolver dual-use - never rewrites resolver config or poisons DNS caches"]
        )
        state.collectorNotes["collect.dns_resolver_dualuse"] = "a=3 b=2 c=3 surface=true"

    }

    static func configureFixtureWave12To14Part3Segment1Leaf2(_ state: inout CollectedState) {
        state.lsQuarantineDbDepth = LsQuarantineDbDepthState(
            quarantineDbPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            lsSupportPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-ls_quarantine_db_depth.plist", "/usr/bin/osascript"],
            quarantineToolHints: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            quarantineDbSurfacePresent: true,
            notes: ["synthetic LS QuarantineEvents depth - never deletes QuarantineEvents rows or clears LS quarantine history"]
        )
        state.collectorNotes["collect.ls_quarantine_db_depth"] = "a=3 b=2 c=3 surface=true"

        state.pamAuthModule = PamAuthModuleState(
            pamConfigPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            pamModulePaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-pam_auth_module.plist", "/usr/bin/osascript"],
            authdSupportPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            pamSurfacePresent: true,
            notes: ["synthetic PAM auth module surface - never installs PAM modules or modifies /etc/pam.d"]
        )
        state.collectorNotes["collect.pam_auth_module"] = "a=3 b=2 c=3 surface=true"

        }

    static func configureFixtureWave12To14Part3Segment2(_ state: inout CollectedState) {
        state.cronAtJobDepth = CronAtJobDepthState(
            cronBinaryPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            crontabPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-cron_at_job_depth.plist", "/usr/bin/osascript"],
            atJobPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            cronAtSurfacePresent: true,
            notes: ["synthetic Cron/at job depth - never installs cron or at jobs outside the lab root"]
        )
        state.collectorNotes["collect.cron_at_job_depth"] = "a=3 b=2 c=3 surface=true"

        state.notesMetadataPlane = NotesMetadataPlaneState(
            notesAppPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            notesStorePaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-notes_metadata_plane.plist", "/usr/bin/osascript"],
            notesContainerPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            notesSurfacePresent: true,
            notes: ["synthetic Notes metadata plane - never reads Notes body contents or exports note secrets"]
        )
        state.collectorNotes["collect.notes_metadata_plane"] = "a=3 b=2 c=3 surface=true"
            }

}
