import Foundation
import RootstockCore

/// ATTACK-VECTOR plane: path-to-impact Checks over CollectedState (not inventory dumps).
///
/// Produces typed findings with ATT&CK mappings, operational constraints,
/// remediation, and BTM caveats.
public enum AttackVectorPlane {
    /// Stable finding / check IDs for registration + tests.
    public static let ids: [String] = [
        ProtectionsWeakVector.id,
        UserWritableLaunchAgentsVector.id,
        LOLExecutionChainVector.id,
        InjectSurfaceVector.id,
        CredOrIdentityPivotVector.id,
        RemoteAccessSurfaceVector.id,
        // Expanded vector plane (path-to-impact / PEASS-class; not inventory dumps).
        TCCFDAPermissionPivotVector.id,
        PrivilegedHelperSygextVector.id,
        MDMManagementGapVector.id,
        BrowserSessionArtifactPivotVector.id,
        WritablePrivilegedPathsVector.id,
        // 2026 coverage gap-driven expansions (non-duplicative of prior 11).
        XPCHelperAbuseSurfaceVector.id,
        PlatformSSOLateralVector.id,
        SecurityProductGapVector.id,
        SystemLaunchDaemonSurfaceVector.id,
        SMAppLoginItemHonestyVector.id,
        // sudoers, periodic, Gatekeeper trust, Automation, Electron.
        SudoersMisconfigSurfaceVector.id,
        PeriodicMaintenanceSurfaceVector.id,
        GatekeeperTrustGapVector.id,
        AutomationExecutionSurfaceVector.id,
        ElectronDevtoolsSurfaceVector.id,
        // Wave-4: quarantine xattr, keychain paths, MDM channel, screen/AX TCC, security CLIs.
        QuarantineXattrSurfaceVector.id,
        KeychainPathSurfaceVector.id,
        MDMManagementChannelSurfaceVector.id,
        ScreenAccessibilitySurfaceVector.id,
        SecurityCLIDualUseVector.id,
        // Wave-5 2026 coverage: ESF, CVE/patch-debt, TCC graph, XPC trust, LC inject, LOOBin multi-stage.
        ESFSensorGapVector.id,
        CVEPatchDebtSuggesterVector.id,
        TCCPermissionGraphDepthVector.id,
        XPCClientValidationSurfaceVector.id,
        LaunchConstraintInjectTruthVector.id,
        LOOBinDualUseMultiStageVector.id,
        // NE/content-filter, auth rights, toolchain dual-use, TM snapshots, mobileconfig sideload.
        NetworkExtensionFilterGapVector.id,
        AuthRightsPrivilegeSurfaceVector.id,
        DeveloperToolchainDualUseVector.id,
        TimeMachineSnapshotAccessVector.id,
        MobileconfigSideloadRiskVector.id,
        // sandbox/entitlements, notarization, virt, Continuity/AirDrop, FileVault escrow.
        SandboxEntitlementThickClientVector.id,
        NotarizationStaplingGapVector.id,
        VirtContainerDualUseVector.id,
        ContinuityAirDropSurfaceVector.id,
        FileVaultEscrowPostureVector.id,
        // ClickFix, RAE, Spotlight/AI-cache, sec mgmt plane, TCC inheritance, SSH agent.
        ClickFixTerminalDeliveryVector.id,
        RemoteAppleEventsLateralVector.id,
        SpotlightAICacheAccessVector.id,
        SecurityMgmtPlaneSurfaceVector.id,
        ThirdPartyTCCInheritanceVector.id,
        SSHAgentKeyPathLateralVector.id,
        // installer design, archive extractors, stealer paths, TCC visibility, MDM parse.
        PackageKitInstallerDesignVector.id,
        ArchiveQuarantineExtractorVector.id,
        InfoStealerPathPlaneVector.id,
        TCCESFVisibilityDepthVector.id,
        MDMProfileParseDepthVector.id,
        // Wave-10 residual pair compounds: receipt×script, extractor×quarantine, stealer×remote, visibility×sensor.
        PackageKitReceiptScriptCompoundVector.id,
        ExtractorQuarantineCompoundVector.id,
        StealerRemoteCompoundVector.id,
        VisibilitySensorCompoundVector.id,
        // URL handlers, launchd overrides, browser extensions, Shortcuts.
        URLSchemeHandlerVector.id,
        LaunchdOverrideDepthVector.id,
        BrowserExtensionDualUseVector.id,
        ShortcutsAppIntentsVector.id,
        URLSchemeRemoteCompoundVector.id,
        LaunchdSecurityDisableCompoundVector.id,
        BrowserExtensionCollectionCompoundVector.id,
        ShortcutsLateralCompoundVector.id,
        // Wave-12 multi-plane (6 net-new themes).
        WeblocInetlocDeliveryVector.id,
        WeblocRemoteCompoundVector.id,
        MailRulesAutomationVector.id,
        MailRulesScriptCompoundVector.id,
        UnifiedLogObservationVector.id,
        UnifiedLogSensorCompoundVector.id,
        DockPersistenceSurfaceVector.id,
        DockRemoteCompoundVector.id,
        OsascriptScptDeliveryVector.id,
        OsascriptRemoteCompoundVector.id,
        NetworkShareMountVector.id,
        NetworkShareRemoteCompoundVector.id,
        // Wave-13 multi-plane (5 net-new themes).
        CalendarRemindersAutomationVector.id,
        CalendarRemoteCompoundVector.id,
        GatekeeperAssessmentHistoryVector.id,
        GatekeeperAssessmentRemoteCompoundVector.id,
        HomebrewPackageDualUseVector.id,
        HomebrewRemoteCompoundVector.id,
        CupsPrintDualUseVector.id,
        CupsRemoteCompoundVector.id,
        ScreenCapturePrivacyDualUseVector.id,
        ScreenCaptureFdaCompoundVector.id,
        // Wave-14 multi-plane (10 net-new themes).
        AutomatorWorkflowVector.id,
        AutomatorWorkflowRemoteCompoundVector.id,
        IcloudDrivePathVector.id,
        IcloudDrivePathRemoteCompoundVector.id,
        BluetoothContinuityDepthVector.id,
        BluetoothContinuityDepthRemoteCompoundVector.id,
        FontValidationDualuseVector.id,
        FontValidationDualuseRemoteCompoundVector.id,
        QuicklookCacheDepthVector.id,
        QuicklookCacheDepthRemoteCompoundVector.id,
        DnsResolverDualuseVector.id,
        DnsResolverDualuseRemoteCompoundVector.id,
        LsQuarantineDbDepthVector.id,
        LsQuarantineDbDepthRemoteCompoundVector.id,
        PamAuthModuleVector.id,
        PamAuthModuleRemoteCompoundVector.id,
        CronAtJobDepthVector.id,
        CronAtJobDepthRemoteCompoundVector.id,
        NotesMetadataPlaneVector.id,
        NotesMetadataPlaneRemoteCompoundVector.id,
        // Wave-15 multi-plane (10 net-new themes).
        PhotosLibraryPathVector.id,
        PhotosLibraryPathRemoteCompoundVector.id,
        VpnConfigDualuseVector.id,
        VpnConfigDualuseRemoteCompoundVector.id,
        SandboxContainerDepthVector.id,
        SandboxContainerDepthRemoteCompoundVector.id,
        XpcMachServiceDepthVector.id,
        XpcMachServiceDepthRemoteCompoundVector.id,
        TmLocalSnapshotDepthVector.id,
        TmLocalSnapshotDepthRemoteCompoundVector.id,
        EmondLegacyDepthVector.id,
        EmondLegacyDepthRemoteCompoundVector.id,
        ScreenSharingArdDepthVector.id,
        ScreenSharingArdDepthRemoteCompoundVector.id,
        KeychainAclPathVector.id,
        KeychainAclPathRemoteCompoundVector.id,
        PythonRuntimeDualuseVector.id,
        PythonRuntimeDualuseRemoteCompoundVector.id,
        ShellPluginManagerVector.id,
        ShellPluginManagerRemoteCompoundVector.id,
        // Wave-16 multi-plane (25 themes).
        AirplayReceiverSurfaceVector.id,
        AirplayReceiverSurfaceRemoteCompoundVector.id,
        HandoffClipboardDepthVector.id,
        HandoffClipboardDepthRemoteCompoundVector.id,
        ImessagePathPlaneVector.id,
        ImessagePathPlaneRemoteCompoundVector.id,
        FacetimeCameraSurfaceVector.id,
        FacetimeCameraSurfaceRemoteCompoundVector.id,
        FinderSyncExtensionVector.id,
        FinderSyncExtensionRemoteCompoundVector.id,
        FileproviderDomainVector.id,
        FileproviderDomainRemoteCompoundVector.id,
        NotificationCenterDepthVector.id,
        NotificationCenterDepthRemoteCompoundVector.id,
        SiriSuggestionsPlaneVector.id,
        SiriSuggestionsPlaneRemoteCompoundVector.id,
        SpotlightImporterDepthVector.id,
        SpotlightImporterDepthRemoteCompoundVector.id,
        ContactsPathPlaneVector.id,
        ContactsPathPlaneRemoteCompoundVector.id,
        CalendarServerPathVector.id,
        CalendarServerPathRemoteCompoundVector.id,
        RemindersCloudPathVector.id,
        RemindersCloudPathRemoteCompoundVector.id,
        MapsLocationPathVector.id,
        MapsLocationPathRemoteCompoundVector.id,
        WeatherWidgetPathVector.id,
        WeatherWidgetPathRemoteCompoundVector.id,
        MusicLibraryPathVector.id,
        MusicLibraryPathRemoteCompoundVector.id,
        BooksPathPlaneVector.id,
        BooksPathPlaneRemoteCompoundVector.id,
        PodcastsPathPlaneVector.id,
        PodcastsPathPlaneRemoteCompoundVector.id,
        TvAppPathPlaneVector.id,
        TvAppPathPlaneRemoteCompoundVector.id,
        HomekitPathPlaneVector.id,
        HomekitPathPlaneRemoteCompoundVector.id,
        HealthPathPlaneVector.id,
        HealthPathPlaneRemoteCompoundVector.id,
        WalletPassPathVector.id,
        WalletPassPathRemoteCompoundVector.id,
        FindmyPathPlaneVector.id,
        FindmyPathPlaneRemoteCompoundVector.id,
        ShortcutsIcloudSyncVector.id,
        ShortcutsIcloudSyncRemoteCompoundVector.id,
        DevicemanagementProfileVector.id,
        DevicemanagementProfileRemoteCompoundVector.id,
        SoftwareupdateCatalogVector.id,
        SoftwareupdateCatalogRemoteCompoundVector.id,
    ]

    public static func allChecks() -> [any Check] {
        baselineChecks()
            + wave10Checks()
            + wave12Checks()
            + wave13Checks()
            + wave14Checks()
            + wave15Checks()
            + wave16Checks()
    }


    private static func baselineChecks() -> [any Check] {
        [
            ProtectionsWeakVector(), UserWritableLaunchAgentsVector(), LOLExecutionChainVector(), InjectSurfaceVector(), CredOrIdentityPivotVector(), RemoteAccessSurfaceVector(), TCCFDAPermissionPivotVector(), PrivilegedHelperSygextVector(), MDMManagementGapVector(), BrowserSessionArtifactPivotVector(), WritablePrivilegedPathsVector(), XPCHelperAbuseSurfaceVector(), PlatformSSOLateralVector(), SecurityProductGapVector(), SystemLaunchDaemonSurfaceVector(), SMAppLoginItemHonestyVector(), SudoersMisconfigSurfaceVector(), PeriodicMaintenanceSurfaceVector(), GatekeeperTrustGapVector(), AutomationExecutionSurfaceVector(), ElectronDevtoolsSurfaceVector(), QuarantineXattrSurfaceVector(), KeychainPathSurfaceVector(), MDMManagementChannelSurfaceVector(), ScreenAccessibilitySurfaceVector(), SecurityCLIDualUseVector(), ESFSensorGapVector(), CVEPatchDebtSuggesterVector(), TCCPermissionGraphDepthVector(), XPCClientValidationSurfaceVector(), LaunchConstraintInjectTruthVector(), LOOBinDualUseMultiStageVector(), NetworkExtensionFilterGapVector(), AuthRightsPrivilegeSurfaceVector(), DeveloperToolchainDualUseVector(), TimeMachineSnapshotAccessVector(), MobileconfigSideloadRiskVector(), SandboxEntitlementThickClientVector(), NotarizationStaplingGapVector(), VirtContainerDualUseVector(), ContinuityAirDropSurfaceVector(), FileVaultEscrowPostureVector(), ClickFixTerminalDeliveryVector(), RemoteAppleEventsLateralVector(), SpotlightAICacheAccessVector(), SecurityMgmtPlaneSurfaceVector(), ThirdPartyTCCInheritanceVector(), SSHAgentKeyPathLateralVector(), PackageKitInstallerDesignVector(), ArchiveQuarantineExtractorVector(), InfoStealerPathPlaneVector(), TCCESFVisibilityDepthVector(), MDMProfileParseDepthVector(),
        ]
    }

    private static func wave10Checks() -> [any Check] {
        [
            PackageKitReceiptScriptCompoundVector(), ExtractorQuarantineCompoundVector(), StealerRemoteCompoundVector(), VisibilitySensorCompoundVector(), URLSchemeHandlerVector(), LaunchdOverrideDepthVector(), BrowserExtensionDualUseVector(), ShortcutsAppIntentsVector(), URLSchemeRemoteCompoundVector(), LaunchdSecurityDisableCompoundVector(), BrowserExtensionCollectionCompoundVector(), ShortcutsLateralCompoundVector(),
        ]
    }

    private static func wave12Checks() -> [any Check] {
        [
            WeblocInetlocDeliveryVector(), WeblocRemoteCompoundVector(), MailRulesAutomationVector(), MailRulesScriptCompoundVector(), UnifiedLogObservationVector(), UnifiedLogSensorCompoundVector(), DockPersistenceSurfaceVector(), DockRemoteCompoundVector(), OsascriptScptDeliveryVector(), OsascriptRemoteCompoundVector(), NetworkShareMountVector(), NetworkShareRemoteCompoundVector(),
        ]
    }

    private static func wave13Checks() -> [any Check] {
        [
            CalendarRemindersAutomationVector(), CalendarRemoteCompoundVector(), GatekeeperAssessmentHistoryVector(), GatekeeperAssessmentRemoteCompoundVector(), HomebrewPackageDualUseVector(), HomebrewRemoteCompoundVector(), CupsPrintDualUseVector(), CupsRemoteCompoundVector(), ScreenCapturePrivacyDualUseVector(), ScreenCaptureFdaCompoundVector(),
        ]
    }

    private static func wave14Checks() -> [any Check] {
        [
            AutomatorWorkflowVector(), AutomatorWorkflowRemoteCompoundVector(), IcloudDrivePathVector(), IcloudDrivePathRemoteCompoundVector(), BluetoothContinuityDepthVector(), BluetoothContinuityDepthRemoteCompoundVector(), FontValidationDualuseVector(), FontValidationDualuseRemoteCompoundVector(), QuicklookCacheDepthVector(), QuicklookCacheDepthRemoteCompoundVector(), DnsResolverDualuseVector(), DnsResolverDualuseRemoteCompoundVector(), LsQuarantineDbDepthVector(), LsQuarantineDbDepthRemoteCompoundVector(), PamAuthModuleVector(), PamAuthModuleRemoteCompoundVector(), CronAtJobDepthVector(), CronAtJobDepthRemoteCompoundVector(), NotesMetadataPlaneVector(), NotesMetadataPlaneRemoteCompoundVector(),
        ]
    }

    private static func wave15Checks() -> [any Check] {
        [
            PhotosLibraryPathVector(), PhotosLibraryPathRemoteCompoundVector(), VpnConfigDualuseVector(), VpnConfigDualuseRemoteCompoundVector(), SandboxContainerDepthVector(), SandboxContainerDepthRemoteCompoundVector(), XpcMachServiceDepthVector(), XpcMachServiceDepthRemoteCompoundVector(), TmLocalSnapshotDepthVector(), TmLocalSnapshotDepthRemoteCompoundVector(), EmondLegacyDepthVector(), EmondLegacyDepthRemoteCompoundVector(), ScreenSharingArdDepthVector(), ScreenSharingArdDepthRemoteCompoundVector(), KeychainAclPathVector(), KeychainAclPathRemoteCompoundVector(), PythonRuntimeDualuseVector(), PythonRuntimeDualuseRemoteCompoundVector(), ShellPluginManagerVector(), ShellPluginManagerRemoteCompoundVector(),
        ]
    }

    private static func wave16Checks() -> [any Check] {
        [
            AirplayReceiverSurfaceVector(), AirplayReceiverSurfaceRemoteCompoundVector(), HandoffClipboardDepthVector(), HandoffClipboardDepthRemoteCompoundVector(), ImessagePathPlaneVector(), ImessagePathPlaneRemoteCompoundVector(), FacetimeCameraSurfaceVector(), FacetimeCameraSurfaceRemoteCompoundVector(), FinderSyncExtensionVector(), FinderSyncExtensionRemoteCompoundVector(), FileproviderDomainVector(), FileproviderDomainRemoteCompoundVector(), NotificationCenterDepthVector(), NotificationCenterDepthRemoteCompoundVector(), SiriSuggestionsPlaneVector(), SiriSuggestionsPlaneRemoteCompoundVector(), SpotlightImporterDepthVector(), SpotlightImporterDepthRemoteCompoundVector(), ContactsPathPlaneVector(), ContactsPathPlaneRemoteCompoundVector(), CalendarServerPathVector(), CalendarServerPathRemoteCompoundVector(), RemindersCloudPathVector(), RemindersCloudPathRemoteCompoundVector(), MapsLocationPathVector(), MapsLocationPathRemoteCompoundVector(), WeatherWidgetPathVector(), WeatherWidgetPathRemoteCompoundVector(), MusicLibraryPathVector(), MusicLibraryPathRemoteCompoundVector(), BooksPathPlaneVector(), BooksPathPlaneRemoteCompoundVector(), PodcastsPathPlaneVector(), PodcastsPathPlaneRemoteCompoundVector(), TvAppPathPlaneVector(), TvAppPathPlaneRemoteCompoundVector(), HomekitPathPlaneVector(), HomekitPathPlaneRemoteCompoundVector(), HealthPathPlaneVector(), HealthPathPlaneRemoteCompoundVector(), WalletPassPathVector(), WalletPassPathRemoteCompoundVector(), FindmyPathPlaneVector(), FindmyPathPlaneRemoteCompoundVector(), ShortcutsIcloudSyncVector(), ShortcutsIcloudSyncRemoteCompoundVector(), DevicemanagementProfileVector(), DevicemanagementProfileRemoteCompoundVector(), SoftwareupdateCatalogVector(), SoftwareupdateCatalogRemoteCompoundVector(),
        ]
    }
}
