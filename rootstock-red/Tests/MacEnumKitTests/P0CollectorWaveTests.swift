import XCTest
import RootstockCore
@testable import MacEnumKit

extension P0CollectorTests {
    func testWave11CollectorsFillState() async throws {
        let context = EvaluationContext.assess(profile: .standard)
        let collectors: [any Collector] = [
            URLSchemeHandlerCollector(),
            LaunchdOverrideDepthCollector(),
            BrowserExtensionDualUseCollector(),
            ShortcutsAppIntentsCollector(),
        ]
        var state = CollectedState()
        for c in collectors {
            let partial = try await c.collect(context: context)
            state.merge(partial)
        }
        XCTAssertNotNil(state.collectorNotes["collect.url_scheme_handler"])
        XCTAssertNotNil(state.collectorNotes["collect.launchd_override_depth"])
        XCTAssertNotNil(state.collectorNotes["collect.browser_extension_dualuse"])
        XCTAssertNotNil(state.collectorNotes["collect.shortcuts_app_intents"])
        // Real host should usually surface at least openers / shortcuts framework paths
        XCTAssertNotNil(state.urlSchemeHandler)
        XCTAssertNotNil(state.launchdOverrideDepth)
        XCTAssertNotNil(state.browserExtensionDualUse)
        XCTAssertNotNil(state.shortcutsAppIntents)
    }

    func testWave12CollectorsFillState() async throws {
        let context = EvaluationContext.assess(profile: .standard)
        let collectors: [any Collector] = [
            WeblocInetlocDeliveryCollector(),
            MailRulesAutomationCollector(),
            UnifiedLogObservationCollector(),
            DockPersistenceSurfaceCollector(),
            OsascriptScptDeliveryCollector(),
            NetworkShareMountCollector()
        ]
        var state = CollectedState()
        for c in collectors {
            let partial = try await c.collect(context: context)
            state.merge(partial)
        }
        XCTAssertNotNil(state.collectorNotes["collect.webloc_inetloc_delivery"])
        XCTAssertNotNil(state.collectorNotes["collect.mail_rules_automation"])
        XCTAssertNotNil(state.collectorNotes["collect.unified_log_observation"])
        XCTAssertNotNil(state.collectorNotes["collect.dock_persistence_surface"])
        XCTAssertNotNil(state.collectorNotes["collect.osascript_scpt_delivery"])
        XCTAssertNotNil(state.collectorNotes["collect.network_share_mount"])
        XCTAssertNotNil(state.weblocInetlocDelivery)
        XCTAssertNotNil(state.mailRulesAutomation)
        XCTAssertNotNil(state.unifiedLogObservation)
        XCTAssertNotNil(state.dockPersistenceSurface)
        XCTAssertNotNil(state.osascriptScptDelivery)
        XCTAssertNotNil(state.networkShareMount)
    }

    func testWave13CollectorsFillState() async throws {
        let context = EvaluationContext.assess(profile: .standard)
        let collectors: [any Collector] = [
            CalendarRemindersAutomationCollector(),
            GatekeeperAssessmentHistoryCollector(),
            HomebrewPackageDualUseCollector(),
            CupsPrintDualUseCollector(),
            ScreenCapturePrivacyDualUseCollector()
        ]
        var state = CollectedState()
        for c in collectors {
            let partial = try await c.collect(context: context)
            state.merge(partial)
        }
        XCTAssertNotNil(state.collectorNotes["collect.calendar_reminders_automation"])
        XCTAssertNotNil(state.collectorNotes["collect.gatekeeper_assessment_history"])
        XCTAssertNotNil(state.collectorNotes["collect.homebrew_package_dualuse"])
        XCTAssertNotNil(state.collectorNotes["collect.cups_print_dualuse"])
        XCTAssertNotNil(state.collectorNotes["collect.screencapture_privacy_dualuse"])
        XCTAssertNotNil(state.calendarRemindersAutomation)
        XCTAssertNotNil(state.gatekeeperAssessmentHistory)
        XCTAssertNotNil(state.homebrewPackageDualUse)
        XCTAssertNotNil(state.cupsPrintDualUse)
        XCTAssertNotNil(state.screenCapturePrivacyDualUse)
    }

    func testWave14CollectorsFillState() async throws {
        let context = EvaluationContext.assess(profile: .standard)
        let collectors: [any Collector] = [
            AutomatorWorkflowCollector(),
            IcloudDrivePathCollector(),
            BluetoothContinuityDepthCollector(),
            FontValidationDualuseCollector(),
            QuicklookCacheDepthCollector(),
            DnsResolverDualuseCollector(),
            LsQuarantineDbDepthCollector(),
            PamAuthModuleCollector(),
            CronAtJobDepthCollector(),
            NotesMetadataPlaneCollector()
        ]
        var state = CollectedState()
        for c in collectors {
            state.merge(try await c.collect(context: context))
        }
        XCTAssertNotNil(state.collectorNotes["collect.automator_workflow"])
        XCTAssertNotNil(state.collectorNotes["collect.icloud_drive_path"])
        XCTAssertNotNil(state.collectorNotes["collect.bluetooth_continuity_depth"])
        XCTAssertNotNil(state.collectorNotes["collect.font_validation_dualuse"])
        XCTAssertNotNil(state.collectorNotes["collect.quicklook_cache_depth"])
        XCTAssertNotNil(state.collectorNotes["collect.dns_resolver_dualuse"])
        XCTAssertNotNil(state.collectorNotes["collect.ls_quarantine_db_depth"])
        XCTAssertNotNil(state.collectorNotes["collect.pam_auth_module"])
        XCTAssertNotNil(state.collectorNotes["collect.cron_at_job_depth"])
        XCTAssertNotNil(state.collectorNotes["collect.notes_metadata_plane"])
        XCTAssertNotNil(state.automatorWorkflow)
        XCTAssertNotNil(state.icloudDrivePath)
        XCTAssertNotNil(state.bluetoothContinuityDepth)
        XCTAssertNotNil(state.fontValidationDualuse)
        XCTAssertNotNil(state.quicklookCacheDepth)
        XCTAssertNotNil(state.dnsResolverDualuse)
        XCTAssertNotNil(state.lsQuarantineDbDepth)
        XCTAssertNotNil(state.pamAuthModule)
        XCTAssertNotNil(state.cronAtJobDepth)
        XCTAssertNotNil(state.notesMetadataPlane)
    }

    func testWave15CollectorsFillState() async throws {
        let context = EvaluationContext.assess(profile: .standard)
        let collectors: [any Collector] = [
            PhotosLibraryPathCollector(),
            VpnConfigDualuseCollector(),
            SandboxContainerDepthCollector(),
            XpcMachServiceDepthCollector(),
            TmLocalSnapshotDepthCollector(),
            EmondLegacyDepthCollector(),
            ScreenSharingArdDepthCollector(),
            KeychainAclPathCollector(),
            PythonRuntimeDualuseCollector(),
            ShellPluginManagerCollector()
        ]
        var state = CollectedState()
        for c in collectors { state.merge(try await c.collect(context: context)) }
        XCTAssertNotNil(state.collectorNotes["collect.photos_library_path"])
        XCTAssertNotNil(state.collectorNotes["collect.vpn_config_dualuse"])
        XCTAssertNotNil(state.collectorNotes["collect.sandbox_container_depth"])
        XCTAssertNotNil(state.collectorNotes["collect.xpc_mach_service_depth"])
        XCTAssertNotNil(state.collectorNotes["collect.tm_local_snapshot_depth"])
        XCTAssertNotNil(state.collectorNotes["collect.emond_legacy_depth"])
        XCTAssertNotNil(state.collectorNotes["collect.screen_sharing_ard_depth"])
        XCTAssertNotNil(state.collectorNotes["collect.keychain_acl_path"])
        XCTAssertNotNil(state.collectorNotes["collect.python_runtime_dualuse"])
        XCTAssertNotNil(state.collectorNotes["collect.shell_plugin_manager"])
        XCTAssertNotNil(state.photosLibraryPath)
        XCTAssertNotNil(state.vpnConfigDualuse)
        XCTAssertNotNil(state.sandboxContainerDepth)
        XCTAssertNotNil(state.xpcMachServiceDepth)
        XCTAssertNotNil(state.tmLocalSnapshotDepth)
        XCTAssertNotNil(state.emondLegacyDepth)
        XCTAssertNotNil(state.screenSharingArdDepth)
        XCTAssertNotNil(state.keychainAclPath)
        XCTAssertNotNil(state.pythonRuntimeDualuse)
        XCTAssertNotNil(state.shellPluginManager)
    }

    func testWave16CollectorsFillState() async throws {
        let context = EvaluationContext.assess(profile: .standard)
        var state = CollectedState()
        for collector in P0CollectorTestFixtures.wave16Collectors {
            state.merge(try await collector.collect(context: context))
        }

        assertWave16CollectorNotes(state)
        assertWave16CollectorState(state)
    }

    private func assertWave16CollectorNotes(_ state: CollectedState) {
        for id in P0CollectorTestFixtures.wave16CollectorIDs {
            XCTAssertNotNil(state.collectorNotes[id], "missing collector note \(id)")
        }
    }

    private func assertWave16CollectorState(_ state: CollectedState) {
        let surfaces: [Any?] = [
            state.airplayReceiverSurface, state.handoffClipboardDepth, state.imessagePathPlane,
            state.facetimeCameraSurface, state.finderSyncExtension, state.fileproviderDomain,
            state.notificationCenterDepth, state.siriSuggestionsPlane, state.spotlightImporterDepth,
            state.contactsPathPlane, state.calendarServerPath, state.remindersCloudPath,
            state.mapsLocationPath, state.weatherWidgetPath, state.musicLibraryPath,
            state.booksPathPlane, state.podcastsPathPlane, state.tvAppPathPlane,
            state.homekitPathPlane, state.healthPathPlane, state.walletPassPath,
            state.findmyPathPlane, state.shortcutsIcloudSync, state.devicemanagementProfile,
            state.softwareupdateCatalog,
        ]
        XCTAssertFalse(surfaces.contains { $0 == nil }, "all Wave-16 states should be populated")
    }







    /// Stock pf/ALF paths must never appear as enterprise contentFilterHints.
    func testNECollectorDoesNotCountStockPfAsContentFilter() async throws {
        let state = try await NetworkExtensionCollector().collect(context: .assess())
        guard let ne = state.networkExtension else {
            XCTFail("networkExtension state required")
            return
        }

        for hint in ne.contentFilterHints {
            assertEnterpriseFilterHint(hint)
        }
        assertNetworkExtensionClassification()
        assertThinFilterGapNote(state, networkExtension: ne)
        assertStockPFIsNotedWhenPresent(ne)
    }

    private func assertEnterpriseFilterHint(_ hint: String) {
        XCTAssertTrue(NetworkExtensionCollector.isEnterpriseContentFilterHint(hint), "stock noise in contentFilterHints: \(hint)")
        XCTAssertFalse(
            hint.contains("/etc/pf.conf") || hint.contains("pf_conf")
                || hint.contains("pf_anchors") || hint.contains("com.apple.alf"),
            "stock pf/ALF must not be contentFilterHints: \(hint)"
        )
    }

    private func assertNetworkExtensionClassification() {
        XCTAssertTrue(NetworkExtensionCollector.isStockNetworkArtifactPath("/etc/pf.conf"))
        XCTAssertTrue(NetworkExtensionCollector.isStockNetworkArtifactPath("/etc/pf.anchors"))
        XCTAssertFalse(NetworkExtensionCollector.isEnterpriseContentFilterHint("pf_conf:/etc/pf.conf"))
        XCTAssertTrue(NetworkExtensionCollector.isEnterpriseContentFilterHint("content_filter_prefs:/Library/Preferences/com.apple.networkextension.filter.plist"))
    }

    private func assertThinFilterGapNote(_ state: CollectedState, networkExtension: NetworkExtensionState) {
        guard networkExtension.contentFilterHints.isEmpty && networkExtension.neAppPaths.isEmpty else { return }
        XCTAssertNotNil(state.collectorNotes["ne.filter_gap"], "thin enterprise filter inventory should set ne.filter_gap")
        XCTAssertTrue((state.collectorNotes[NetworkExtensionCollector.id] ?? "").contains("contentFilter=0"))
    }

    private func assertStockPFIsNotedWhenPresent(_ networkExtension: NetworkExtensionState) {
        guard FileManager.default.fileExists(atPath: "/etc/pf.conf") else { return }
        let notes = networkExtension.notes.joined(separator: " ")
        XCTAssertTrue(notes.contains("stock_os_network") || notes.contains("pf_conf"), "stock pf should be noted separately when present")
    }

    /// SystemProfiler prefs names must not be treated as configuration-profile sideload surface.
    func testConfigProfilePrefFilterExcludesSystemProfiler() {
        XCTAssertFalse(
            ConfigProfileSideloadCollector.isConfigurationProfilePrefName(
                "com.apple.SystemProfiler.plist"
            )
        )
        XCTAssertFalse(
            ConfigProfileSideloadCollector.isConfigurationProfilePrefName(
                "com.apple.systemprofiler.plist"
            )
        )
        XCTAssertTrue(
            ConfigProfileSideloadCollector.isConfigurationProfilePrefName(
                "com.example.vpn.mobileconfig"
            )
        )
        XCTAssertTrue(
            ConfigProfileSideloadCollector.isConfigurationProfilePrefName(
                "com.apple.managedclient.plist"
            )
        )
        XCTAssertTrue(
            ConfigProfileSideloadCollector.isConfigurationProfilePrefName(
                "com.jamf.configurationprofiles.plist"
            )
        )
        // Bare "profile" without config/mdm context is insufficient
        XCTAssertFalse(
            ConfigProfileSideloadCollector.isConfigurationProfilePrefName(
                "com.example.myprofile.plist"
            )
        )
    }

    func testConfigProfileCollectorDoesNotListSystemProfilerAsHint() async throws {
        let state = try await ConfigProfileSideloadCollector().collect(context: .assess())
        guard let cfg = state.configProfileSideload else {
            XCTFail("configProfileSideload required")
            return
        }
        for hint in cfg.downloadsProfileHints + cfg.userMobileconfigPaths {
            let lower = hint.lowercased()
            XCTAssertFalse(
                lower.contains("systemprofiler"),
                "SystemProfiler must not appear as sideload surface: \(hint)"
            )
        }
    }

    /// Stock Apple ES paths must never appear as third-party clients (sensor-gap honesty).
    func testESFCollectorDoesNotCountAppleInfrastructureAsClients() async throws {
        let state = try await ESFEndpointSecurityCollector().collect(context: .assess())
        guard let esf = state.esf else {
            XCTFail("esf state required")
            return
        }
        // endpointsecurityd / framework / bare SystemExtensions root are Apple infra.
        for path in esf.clientPaths {
            XCTAssertFalse(
                ESFEndpointSecurityCollector.isAppleInfrastructurePath(path),
                "Apple infra must not be clientPaths: \(path)"
            )
            XCTAssertFalse(
                path == "/usr/libexec/endpointsecurityd",
                "endpointsecurityd counted as client"
            )
            XCTAssertFalse(
                path == "/Library/SystemExtensions",
                "bare SystemExtensions directory counted as client"
            )
            XCTAssertFalse(
                path.hasPrefix("/System/Library/Frameworks/EndpointSecurity"),
                "framework counted as client: \(path)"
            )
        }
        // Notes should still acknowledge Apple infrastructure when present.
        let notesBlob = esf.notes.joined(separator: " ")
        let noteMentionsInfra =
            notesBlob.contains("apple_infra")
            || notesBlob.contains("endpointsecurityd")
            || notesBlob.contains("EndpointSecurity.framework")
        let frameworkKnown = esf.frameworkPresent == true
        XCTAssertTrue(
            noteMentionsInfra || frameworkKnown || !FileManager.default.fileExists(
                atPath: "/usr/libexec/endpointsecurityd"
            ),
            "collector should record Apple infra in notes/framework when present on host"
        )
        // Collector note uses thirdPartyClients token for gap detection.
        let cnote = state.collectorNotes[ESFEndpointSecurityCollector.id] ?? ""
        XCTAssertTrue(
            cnote.contains("thirdPartyClients="),
            "collector note must report thirdPartyClients= count; got \(cnote)"
        )
    }

    /// Key-adjacent entitlement parse: other `<true/>` keys must not set get-task-allow.
    func testLaunchConstraintEntitlementBoolKeyAdjacent() {
        let xmlWithUnrelatedTrue = """
        <?xml version="1.0"?>
        <plist>
        <dict>
            <key>com.apple.security.app-sandbox</key>
            <true/>
            <key>com.apple.security.get-task-allow</key>
            <false/>
            <key>com.apple.security.cs.disable-library-validation</key>
            <true/>
        </dict>
        </plist>
        """
        // Would FAIL if parser used global text.contains("<true").
        XCTAssertEqual( LaunchConstraintCollector.entitlementBool( in: xmlWithUnrelatedTrue, key: "com.apple.security.get-task-allow" ), false, "get-task-allow must be false when key-adjacent value is false" )
        XCTAssertEqual( LaunchConstraintCollector.entitlementBool( in: xmlWithUnrelatedTrue, key: "com.apple.security.cs.disable-library-validation" ), true )
        XCTAssertEqual( LaunchConstraintCollector.entitlementBool( in: xmlWithUnrelatedTrue, key: "com.apple.security.app-sandbox" ), true )
        XCTAssertNil( LaunchConstraintCollector.entitlementBool( in: xmlWithUnrelatedTrue, key: "com.apple.security.cs.allow-dyld-environment-variables" ), "absent key must be nil" )

        let getTaskAllowTrue = """
        <key>com.apple.security.get-task-allow</key>
        <true/>
        <key>com.apple.security.app-sandbox</key>
        <false/>
        """
        XCTAssertEqual( LaunchConstraintCollector.entitlementBool( in: getTaskAllowTrue, key: "com.apple.security.get-task-allow" ), true )
        XCTAssertEqual( LaunchConstraintCollector.entitlementBool( in: getTaskAllowTrue, key: "com.apple.security.app-sandbox" ), false )

        // Global true pollution fixture (the bug class).
        let pollution = """
        <key>some.other.entitlement</key>
        <true/>
        <key>com.apple.security.get-task-allow</key>
        <false/>
        """
        XCTAssertEqual( LaunchConstraintCollector.entitlementBool( in: pollution, key: "com.apple.security.get-task-allow" ), false, "unrelated <true/> must not force get-task-allow" )
    }
}
