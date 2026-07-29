/// Assess collector registry: host inventory modules feeding CollectedState for vectors/checks.
import Foundation
import RootstockCore
import MacIdentityKit
import MacMdmKit
import MacPersistKit

/// Default assess collector set for RootstockRed.
public enum EnumModuleRegistry {
    public static func allCollectors() -> [any Collector] {
        foundationalCollectors
            + wave5To7Collectors
            + wave8To9Collectors
            + wave11To14Collectors
            + wave15To16Collectors
    }

    private static let foundationalCollectors: [any Collector] = [
        HostCollector(), SecurityProductsCollector(), RunningAppsCollector(), LaunchdCollector(),
        PersistAuditCollector(), TCCCollector(), CredPathsCollector(), LOOBinsCollector(),
        ProtectionsCollector(), MdmPostureCollector(), IdentityPostureCollector(),
        LoginItemsBTMCollector(), NetworkCollector(), CodesignCollector(), DylibRiskCollector(),
        InjectabilityCollector(), BrowserMetaCollector(), XPCHelpersCollector(), SystemExtensionsCollector(),
    ]

    private static let wave5To7Collectors: [any Collector] = [
        ESFEndpointSecurityCollector(), PatchDebtCollector(), TCCPermissionGraphCollector(),
        LaunchConstraintCollector(), NetworkExtensionCollector(), AuthRightsCollector(),
        DeveloperToolchainCollector(), TimeMachineCollector(), ConfigProfileSideloadCollector(),
        AppSandboxEntitlementsCollector(), NotarizationStaplingCollector(),
        VirtualizationContainersCollector(), ContinuityAirDropCollector(), FileVaultEscrowCollector(),
    ]

    private static let wave8To9Collectors: [any Collector] = [
        ClickFixTerminalDeliveryCollector(), RemoteAppleEventsCollector(), SpotlightAICacheCollector(),
        SecurityMgmtPlaneCollector(), ThirdPartyTCCInheritanceCollector(), SSHAgentKeyPathCollector(),
        PackageKitInstallerDesignCollector(), ArchiveQuarantineExtractorCollector(),
        InfoStealerPathPlaneCollector(), TCCESFVisibilityDepthCollector(), MDMProfileParseDepthCollector(),
    ]

    private static let wave11To14Collectors: [any Collector] = [
        URLSchemeHandlerCollector(), LaunchdOverrideDepthCollector(), BrowserExtensionDualUseCollector(),
        ShortcutsAppIntentsCollector(), WeblocInetlocDeliveryCollector(), MailRulesAutomationCollector(),
        UnifiedLogObservationCollector(), DockPersistenceSurfaceCollector(), OsascriptScptDeliveryCollector(),
        NetworkShareMountCollector(), CalendarRemindersAutomationCollector(),
        GatekeeperAssessmentHistoryCollector(), HomebrewPackageDualUseCollector(),
        CupsPrintDualUseCollector(), ScreenCapturePrivacyDualUseCollector(), AutomatorWorkflowCollector(),
        IcloudDrivePathCollector(), BluetoothContinuityDepthCollector(), FontValidationDualuseCollector(),
        QuicklookCacheDepthCollector(), DnsResolverDualuseCollector(), LsQuarantineDbDepthCollector(),
        PamAuthModuleCollector(), CronAtJobDepthCollector(), NotesMetadataPlaneCollector(),
    ]

    private static let wave15To16Collectors: [any Collector] = [
        PhotosLibraryPathCollector(), VpnConfigDualuseCollector(), SandboxContainerDepthCollector(),
        XpcMachServiceDepthCollector(), TmLocalSnapshotDepthCollector(), EmondLegacyDepthCollector(),
        ScreenSharingArdDepthCollector(), KeychainAclPathCollector(), PythonRuntimeDualuseCollector(),
        ShellPluginManagerCollector(), AirplayReceiverSurfaceCollector(), HandoffClipboardDepthCollector(),
        ImessagePathPlaneCollector(), FacetimeCameraSurfaceCollector(), FinderSyncExtensionCollector(),
        FileproviderDomainCollector(), NotificationCenterDepthCollector(), SiriSuggestionsPlaneCollector(),
        SpotlightImporterDepthCollector(), ContactsPathPlaneCollector(), CalendarServerPathCollector(),
        RemindersCloudPathCollector(), MapsLocationPathCollector(), WeatherWidgetPathCollector(),
        MusicLibraryPathCollector(), BooksPathPlaneCollector(), PodcastsPathPlaneCollector(),
        TvAppPathPlaneCollector(), HomekitPathPlaneCollector(), HealthPathPlaneCollector(),
        WalletPassPathCollector(), FindmyPathPlaneCollector(), ShortcutsIcloudSyncCollector(),
        DevicemanagementProfileCollector(), SoftwareupdateCatalogCollector(),
    ]

    public static func defaultRegistry(checks: [any Check] = []) -> ModuleRegistry {
        ModuleRegistry(collectors: allCollectors(), checks: checks)
    }
}
