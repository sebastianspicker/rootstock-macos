import Foundation
import RootstockBlueCore

extension HardeningAssessment {
    static func containsAny(_ value: String, terms: [String]) -> Bool {
        terms.contains { value.contains($0) }
    }

    static func assessControlFindings(_ events: [EventEnvelope]) -> [Finding] {
        [assessProtections(events), assessRemoteAccess(events), assessLaunchdOverrides(events), assessSudoers(events), assessShellProfiles(events), assessEmond(events), assessSystemExtensions(events), assessSecurityCoverage(events)].flatMap { $0 }
    }

    static func assessWaveFourFindings(_ events: [EventEnvelope]) -> [Finding] {
        [assessPrivHelpers(events), assessFolderActions(events), assessLoginHooks(events), assessAccountPosture(events), assessSoftwareUpdate(events), assessLockdownMode(events)].flatMap { $0 }
    }

    static func assessWaveFiveFindings(_ events: [EventEnvelope]) -> [Finding] {
        [assessAuthPlugins(events), assessNetUsage(events), assessCodesign(events), assessKeychainMeta(events), assessARDAllLocalUsers(events)].flatMap { $0 }
    }

    static func assessWaveSixFindings(_ events: [EventEnvelope]) -> [Finding] {
        [assessTrashSensitive(events), assessSpotlightSensitive(events), assessFirefoxSuspiciousDownload(events), assessNotificationSensitive(events), assessQuickLookSensitive(events), assessScreenTimeSuspicious(events), assessICloudDesktopDocuments(events), assessSavedStateSuspicious(events)].flatMap { $0 }
    }

    static func assessWaveSevenFindings(_ events: [EventEnvelope]) -> [Finding] {
        [assessCookieEvilDomain(events), assessBookmarkEvilDomain(events), assessOfficeMRUSensitive(events), assessPrintSensitiveJob(events), assessNotesSensitiveMarker(events), assessIDeviceBackupUnencrypted(events), assessMSRDCRemoteConnection(events), assessCloudSyncExfilProvider(events)].flatMap { $0 }
    }

    static func assessWaveEightToTwelveFindings(_ events: [EventEnvelope]) -> [Finding] {
        [assessPackageKitInstallerDesign(events), assessArchiveQuarantineExtractor(events), assessInfoStealerPathPlane(events), assessTCCESFVisibilityDepth(events), assessURLSchemeHandler(events), assessLaunchdOverrideDepth(events), assessBrowserExtensionDualUse(events), assessShortcutsAppIntents(events), assessWeblocInetloc(events), assessMailRulesAutomation(events), assessUnifiedLogObservation(events), assessDockPersistenceSurface(events), assessOsascriptScptDelivery(events), assessNetworkShareMount(events)].flatMap { $0 }
    }

    static func assessWaveThirteenToFourteenFindings(_ events: [EventEnvelope]) -> [Finding] {
        [assessCalendarRemindersAutomation(events), assessGatekeeperAssessmentHistory(events), assessHomebrewPackageDualUse(events), assessCupsPrintDualUse(events), assessScreenCapturePrivacyDualUse(events), assessAutomatorWorkflow(events), assessIcloudDrivePath(events), assessBluetoothContinuityDepth(events), assessFontValidationDualuse(events), assessQuicklookCacheDepth(events), assessDnsResolverDualuse(events), assessLsQuarantineDbDepth(events), assessPamAuthModule(events), assessCronAtJobDepth(events), assessNotesMetadataPlane(events)].flatMap { $0 }
    }

    static func assessWaveFifteenFindings(_ events: [EventEnvelope]) -> [Finding] {
        [assessPhotosLibraryPath(events), assessVpnConfigDualuse(events), assessSandboxContainerDepth(events), assessXpcMachServiceDepth(events), assessTmLocalSnapshotDepth(events), assessEmondLegacyDepth(events), assessScreenSharingArdDepth(events), assessKeychainAclPath(events), assessPythonRuntimeDualuse(events), assessShellPluginManager(events)].flatMap { $0 }
    }

    static func assessWaveSixteenFindings(_ events: [EventEnvelope]) -> [Finding] {
        [assessAirplayReceiverSurface(events), assessHandoffClipboardDepth(events), assessImessagePathPlane(events), assessFacetimeCameraSurface(events), assessFinderSyncExtension(events), assessFileproviderDomain(events), assessNotificationCenterDepth(events), assessSiriSuggestionsPlane(events), assessSpotlightImporterDepth(events), assessContactsPathPlane(events), assessCalendarServerPath(events), assessRemindersCloudPath(events), assessMapsLocationPath(events), assessWeatherWidgetPath(events), assessMusicLibraryPath(events), assessBooksPathPlane(events), assessPodcastsPathPlane(events), assessTvAppPathPlane(events), assessHomekitPathPlane(events), assessHealthPathPlane(events), assessWalletPassPath(events), assessFindmyPathPlane(events), assessShortcutsIcloudSync(events), assessDevicemanagementProfile(events), assessSoftwareupdateCatalog(events)].flatMap { $0 }
    }

    static func offlineFoundationEvents(_ source: ImageSource) throws -> [EventEnvelope] {
        try [HostIRPosture.enumerateOffline(source: source), ShellProfilesParser().parse(source: source), EmondParser().parse(source: source), SudoersParser().parse(source: source), LaunchdOverridesParser().parse(source: source), SystemExtensionsParser().parse(source: source), PrivHelpersParser().parse(source: source), FolderActionsParser().parse(source: source), LoginHooksParser().parse(source: source)].flatMap { $0 }
    }

    static func offlineWaveFiveEvents(_ source: ImageSource) throws -> [EventEnvelope] {
        try [AuthPluginsParser().parse(source: source), NetUsageParser().parse(source: source), USBHistoryParser().parse(source: source), KeychainMetaParser().parse(source: source), CodesignParser().parse(source: source), ARDParser().parse(source: source)].flatMap { $0 }
    }

    static func offlineWaveSixEvents(_ source: ImageSource) throws -> [EventEnvelope] {
        try [SpotlightParser().parse(source: source), TrashParser().parse(source: source), DocRevisionsParser().parse(source: source), SavedStateParser().parse(source: source), FirefoxParser().parse(source: source), NotificationsParser().parse(source: source), QuickLookParser().parse(source: source), ScreenTimeParser().parse(source: source), ICloudParser().parse(source: source)].flatMap { $0 }
    }

    static func offlineWaveSevenEvents(_ source: ImageSource) throws -> [EventEnvelope] {
        try [CookiesParser().parse(source: source), BookmarksParser().parse(source: source), OfficeMRUParser().parse(source: source), PrintJobsParser().parse(source: source), NotesParser().parse(source: source), IDeviceBackupParser().parse(source: source), MSRDCParser().parse(source: source), CloudSyncParser().parse(source: source)].flatMap { $0 }
    }

    static func offlineWaveEightToTwelveEvents(_ source: ImageSource) throws -> [EventEnvelope] {
        try [PackageKitDesignParser().parse(source: source), ArchiveExtractorParser().parse(source: source), InfoStealerPathParser().parse(source: source), TCCESFVisibilityParser().parse(source: source), URLSchemeHandlerParser().parse(source: source), LaunchdOverrideDepthParser().parse(source: source), BrowserExtensionDualUseParser().parse(source: source), ShortcutsAppIntentsParser().parse(source: source), WeblocInetlocParser().parse(source: source), MailRulesAutomationParser().parse(source: source), UnifiedLogObservationParser().parse(source: source), DockPersistenceSurfaceParser().parse(source: source), OsascriptScptDeliveryParser().parse(source: source), NetworkShareMountParser().parse(source: source)].flatMap { $0 }
    }

    static func offlineWaveThirteenToFourteenEvents(_ source: ImageSource) throws -> [EventEnvelope] {
        try [CalendarRemindersAutomationParser().parse(source: source), GatekeeperAssessmentHistoryParser().parse(source: source), HomebrewPackageDualUseParser().parse(source: source), CupsPrintDualUseParser().parse(source: source), ScreenCapturePrivacyDualUseParser().parse(source: source), AutomatorWorkflowParser().parse(source: source), IcloudDrivePathParser().parse(source: source), BluetoothContinuityDepthParser().parse(source: source), FontValidationDualuseParser().parse(source: source), QuicklookCacheDepthParser().parse(source: source), DnsResolverDualuseParser().parse(source: source), LsQuarantineDbDepthParser().parse(source: source), PamAuthModuleParser().parse(source: source), CronAtJobDepthParser().parse(source: source), NotesMetadataPlaneParser().parse(source: source)].flatMap { $0 }
    }

    static func offlineWaveFifteenEvents(_ source: ImageSource) throws -> [EventEnvelope] {
        try [PhotosLibraryPathParser().parse(source: source), VpnConfigDualuseParser().parse(source: source), SandboxContainerDepthParser().parse(source: source), XpcMachServiceDepthParser().parse(source: source), TmLocalSnapshotDepthParser().parse(source: source), EmondLegacyDepthParser().parse(source: source), ScreenSharingArdDepthParser().parse(source: source), KeychainAclPathParser().parse(source: source), PythonRuntimeDualuseParser().parse(source: source), ShellPluginManagerParser().parse(source: source)].flatMap { $0 }
    }

    static func offlineWaveSixteenEvents(_ source: ImageSource) throws -> [EventEnvelope] {
        try [AirplayReceiverSurfaceParser().parse(source: source), HandoffClipboardDepthParser().parse(source: source), ImessagePathPlaneParser().parse(source: source), FacetimeCameraSurfaceParser().parse(source: source), FinderSyncExtensionParser().parse(source: source), FileproviderDomainParser().parse(source: source), NotificationCenterDepthParser().parse(source: source), SiriSuggestionsPlaneParser().parse(source: source), SpotlightImporterDepthParser().parse(source: source), ContactsPathPlaneParser().parse(source: source), CalendarServerPathParser().parse(source: source), RemindersCloudPathParser().parse(source: source), MapsLocationPathParser().parse(source: source), WeatherWidgetPathParser().parse(source: source), MusicLibraryPathParser().parse(source: source), BooksPathPlaneParser().parse(source: source), PodcastsPathPlaneParser().parse(source: source), TvAppPathPlaneParser().parse(source: source), HomekitPathPlaneParser().parse(source: source), HealthPathPlaneParser().parse(source: source), WalletPassPathParser().parse(source: source), FindmyPathPlaneParser().parse(source: source), ShortcutsIcloudSyncParser().parse(source: source), DevicemanagementProfileParser().parse(source: source), SoftwareupdateCatalogParser().parse(source: source)].flatMap { $0 }
    }
}
