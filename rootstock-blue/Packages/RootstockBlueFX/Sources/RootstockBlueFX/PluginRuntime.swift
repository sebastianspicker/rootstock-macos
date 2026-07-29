import Foundation
import RootstockBlueCore

public protocol ArtifactParser: Sendable {
    var manifest: PluginManifest { get }
    func parse(source: ImageSource) throws -> [EventEnvelope]
}

public struct PluginRuntime: Sendable {
    public var parsers: [any ArtifactParser]

    public init(parsers: [any ArtifactParser] = PluginRuntime.defaultTier1()) {
        self.parsers = parsers
    }

    public static func defaultTier1() -> [any ArtifactParser] {
        coreParsers + persistenceParsers + forensicsParsers + coverageParsers
            + wave8Parsers + wave11Parsers + wave12Parsers + wave13Parsers
            + wave14Parsers + wave15Parsers + wave16Parsers
    }

    private static var coreParsers: [any ArtifactParser] {
        [
            // Tier-1 IR / host state
            TCCParser(),
            QuarantineParser(),
            AutostartParser(),
            UsersParser(),
            FSEventsParser(),
            TerminalParser(),
            XProtectParser(),
            BasicInfoParser(),
            // Tier-1 persistence / auth expansion (BlueTeam 2026)
            CronParser(),
            LoginItemsParser(),
            SystemExtensionsParser(),
            UtmpxParser(),
        ]
    }

    private static var persistenceParsers: [any ArtifactParser] {
        [
            // Tier-2 post-incident forensics (always registered in default engine)
            SafariParser(),
            ChromiumParser(),
            KnowledgeCParser(),
            RecentItemsParser(),
            InstallHistoryParser(),
            DockParser(),
            // 2026 coverage families
            BTMParser(),
            WifiParser(),
            ConfigProfilesParser(),
            SSHArtifactsParser(),
            // BlueTeam 2026 offline expansion
            BiomeParser(),
            BrowserExtensionsParser(),
            GatekeeperHistoryParser(),
            NetworkLocationParser(),
        ]
    }

    private static var forensicsParsers: [any ArtifactParser] {
        [
            // Wave-3 2026 coverage ROI (beyond §7.1–§7.2)
            ShellProfilesParser(),
            EmondParser(),
            SudoersParser(),
            LaunchdOverridesParser(),
            // Wave-4 2026 coverage ROI (beyond §7.1–§7.9)
            PrivHelpersParser(),
            FolderActionsParser(),
            LoginHooksParser(),
        ]
    }

    private static var coverageParsers: [any ArtifactParser] {
        [
            // Wave-5 2026 coverage ROI (beyond §7.1–§7.10)
            AuthPluginsParser(),
            NetUsageParser(),
            USBHistoryParser(),
            KeychainMetaParser(),
            CodesignParser(),
            ARDParser(),
            // Wave-6 2026 coverage ROI (beyond §7.1–§7.11)
            SpotlightParser(),
            TrashParser(),
            DocRevisionsParser(),
            SavedStateParser(),
            FirefoxParser(),
            NotificationsParser(),
            QuickLookParser(),
            ScreenTimeParser(),
            ICloudParser(),
            // Wave-7 2026 coverage ROI (beyond §7.1–§7.12)
            CookiesParser(),
            BookmarksParser(),
            OfficeMRUParser(),
            PrintJobsParser(),
            NotesParser(),
            IDeviceBackupParser(),
            MSRDCParser(),
            CloudSyncParser(),
        ]
    }

    private static var wave8Parsers: [any ArtifactParser] {
        [
            // Wave-8 residual red↔blue pair parsers
            PackageKitDesignParser(),
            ArchiveExtractorParser(),
            InfoStealerPathParser(),
            TCCESFVisibilityParser(),
        ]
    }

    private static var wave11Parsers: [any ArtifactParser] {
        [
            // Wave-11 multi-plane red↔blue pair parsers
            URLSchemeHandlerParser(),
            LaunchdOverrideDepthParser(),
            BrowserExtensionDualUseParser(),
            ShortcutsAppIntentsParser(),
        ]
    }

    private static var wave12Parsers: [any ArtifactParser] {
        [
            // Wave-12 multi-plane red↔blue pair parsers
            WeblocInetlocParser(),
            MailRulesAutomationParser(),
            UnifiedLogObservationParser(),
            DockPersistenceSurfaceParser(),
            OsascriptScptDeliveryParser(),
            NetworkShareMountParser(),
        ]
    }

    private static var wave13Parsers: [any ArtifactParser] {
        [
            // Wave-13 multi-plane red↔blue pair parsers
            CalendarRemindersAutomationParser(),
            GatekeeperAssessmentHistoryParser(),
            HomebrewPackageDualUseParser(),
            CupsPrintDualUseParser(),
            ScreenCapturePrivacyDualUseParser(),
        ]
    }

    private static var wave14Parsers: [any ArtifactParser] {
        [
            // Wave-14 multi-plane red↔blue pair parsers
            AutomatorWorkflowParser(),
            IcloudDrivePathParser(),
            BluetoothContinuityDepthParser(),
            FontValidationDualuseParser(),
            QuicklookCacheDepthParser(),
            DnsResolverDualuseParser(),
            LsQuarantineDbDepthParser(),
            PamAuthModuleParser(),
            CronAtJobDepthParser(),
            NotesMetadataPlaneParser(),
        ]
    }

    private static var wave15Parsers: [any ArtifactParser] {
        [
            // Wave-15 multi-plane red↔blue pair parsers
            PhotosLibraryPathParser(),
            VpnConfigDualuseParser(),
            SandboxContainerDepthParser(),
            XpcMachServiceDepthParser(),
            TmLocalSnapshotDepthParser(),
            EmondLegacyDepthParser(),
            ScreenSharingArdDepthParser(),
            KeychainAclPathParser(),
            PythonRuntimeDualuseParser(),
            ShellPluginManagerParser(),
        ]
    }

    private static var wave16Parsers: [any ArtifactParser] {
        [
            // Wave-16 multi-plane red↔blue pair parsers (25)
            AirplayReceiverSurfaceParser(),
            HandoffClipboardDepthParser(),
            ImessagePathPlaneParser(),
            FacetimeCameraSurfaceParser(),
            FinderSyncExtensionParser(),
            FileproviderDomainParser(),
            NotificationCenterDepthParser(),
            SiriSuggestionsPlaneParser(),
            SpotlightImporterDepthParser(),
            ContactsPathPlaneParser(),
            CalendarServerPathParser(),
            RemindersCloudPathParser(),
            MapsLocationPathParser(),
            WeatherWidgetPathParser(),
            MusicLibraryPathParser(),
            BooksPathPlaneParser(),
            PodcastsPathPlaneParser(),
            TvAppPathPlaneParser(),
            HomekitPathPlaneParser(),
            HealthPathPlaneParser(),
            WalletPassPathParser(),
            FindmyPathPlaneParser(),
            ShortcutsIcloudSyncParser(),
            DevicemanagementProfileParser(),
            SoftwareupdateCatalogParser(),
        ]
    }

    /// Explicit post-incident forensic set (alias of full default for CLI messaging).
    public static func defaultForensics() -> [any ArtifactParser] {
        defaultTier1()
    }

    public func parserIDs() -> [String] {
        parsers.map(\.manifest.id)
    }
}
