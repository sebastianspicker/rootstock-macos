import Foundation
import RootstockCore

/// Lab action registry (not linked into default assess executable).
public struct ActionRegistry: Sendable {
    public var actions: [any Action]

    public init(actions: [any Action] = []) {
        self.actions = actions
    }

    /// Minimal registry containing only the no-op action.
    public static func scaffold() -> ActionRegistry {
        ActionRegistry(actions: [NoopLabAction()])
    }

    /// Complete lab registry with consent checks and dry-run defaults.
    public static func production() -> ActionRegistry {
        ActionRegistry(actions: foundationalActions + waveFiveToNineActions + waveElevenToSixteenActions)
    }

    private static var foundationalActions: [any Action] {
        [
            NoopLabAction(),
            LaunchAgentLabAction(),
            DylibSurfaceLabAction(),
            ShellRCLabAction(),
            CronMarkerLabAction(),
            DyldEnvLabAction(),
            LoginItemMarkerLabAction(),
            AtomicIOCLabAction(),
            XPCHelperPlanLabAction(),
            PeriodicMarkerLabAction(),
            SudoersPlanLabAction(),
            ESFExpectLabAction(),
            QuarantinePlanLabAction(),
            KeychainPathPlanLabAction(),
            XattrDetectPairLabAction(),
            // Wave-5 2026 coverage lab surface
            ESFSensorPlanLabAction(),
            TCCGraphPlanLabAction(),
            PatchDebtPlanLabAction(),
            LaunchConstraintPlanLabAction(),
            LOLMultistagePlanLabAction(),
        ]
    }

    private static var waveFiveToNineActions: [any Action] {
        [
            // Wave-6 2026 coverage lab surface
            NetworkExtensionPlanLabAction(),
            AuthRightsPlanLabAction(),
            DeveloperToolchainPlanLabAction(),
            TimeMachinePlanLabAction(),
            MobileconfigSideloadPlanLabAction(),
            // Wave-7 2026 coverage lab surface
            AppSandboxPlanLabAction(),
            NotarizationPlanLabAction(),
            VirtualizationPlanLabAction(),
            ContinuityAirDropPlanLabAction(),
            FileVaultEscrowPlanLabAction(),
        ]
    }

    private static var waveElevenToSixteenActions: [any Action] {
        [
            // Wave-8 2026 coverage lab surface
            ClickFixTerminalPlanLabAction(),
            RemoteAppleEventsPlanLabAction(),
            SpotlightAICachePlanLabAction(),
            SecurityMgmtPlanePlanLabAction(),
            ThirdPartyTCCInheritancePlanLabAction(),
            SSHAgentKeyPathPlanLabAction(),
            // Wave-9 2026 coverage lab surface
            PackageKitInstallerPlanLabAction(),
            ArchiveQuarantinePlanLabAction(),
            InfoStealerPathPlanLabAction(),
            TCCESFVisibilityPlanLabAction(),
            MDMProfileParsePlanLabAction(),
            // Wave-11 2026 coverage lab surface
            URLSchemeHandlerPlanLabAction(),
            LaunchdOverrideDepthPlanLabAction(),
            BrowserExtensionDualUsePlanLabAction(),
            ShortcutsAppIntentsPlanLabAction(),
            // Wave-12 2026 coverage lab surface
            WeblocInetlocPlanLabAction(),
            MailRulesAutomationPlanLabAction(),
            UnifiedLogObservationPlanLabAction(),
            DockPersistencePlanLabAction(),
            OsascriptScptPlanLabAction(),
            NetworkShareMountPlanLabAction(),
            // Wave-13 2026 coverage lab surface
            CalendarRemindersPlanLabAction(),
            GatekeeperAssessmentHistoryPlanLabAction(),
            HomebrewPackagePlanLabAction(),
            CupsPrintPlanLabAction(),
            ScreenCapturePrivacyPlanLabAction(),
            // Wave-14 2026 coverage lab surface
            AutomatorWorkflowPlanLabAction(),
            IcloudDrivePathPlanLabAction(),
            BluetoothContinuityDepthPlanLabAction(),
            FontValidationDualusePlanLabAction(),
            QuicklookCacheDepthPlanLabAction(),
            DnsResolverDualusePlanLabAction(),
            LsQuarantineDbDepthPlanLabAction(),
            PamAuthModulePlanLabAction(),
            CronAtJobDepthPlanLabAction(),
            NotesMetadataPlanePlanLabAction(),
            // Wave-15 2026 coverage lab surface
            PhotosLibraryPathPlanLabAction(),
            VpnConfigDualusePlanLabAction(),
            SandboxContainerDepthPlanLabAction(),
            XpcMachServiceDepthPlanLabAction(),
            TmLocalSnapshotDepthPlanLabAction(),
            EmondLegacyDepthPlanLabAction(),
            ScreenSharingArdDepthPlanLabAction(),
            KeychainAclPathPlanLabAction(),
            PythonRuntimeDualusePlanLabAction(),
            ShellPluginManagerPlanLabAction(),
            // Wave-16 multi-plane lab surface
            AirplayReceiverSurfacePlanLabAction(),
            HandoffClipboardDepthPlanLabAction(),
            ImessagePathPlanePlanLabAction(),
            FacetimeCameraSurfacePlanLabAction(),
            FinderSyncExtensionPlanLabAction(),
            FileproviderDomainPlanLabAction(),
            NotificationCenterDepthPlanLabAction(),
            SiriSuggestionsPlanePlanLabAction(),
            SpotlightImporterDepthPlanLabAction(),
            ContactsPathPlanePlanLabAction(),
            CalendarServerPathPlanLabAction(),
            RemindersCloudPathPlanLabAction(),
            MapsLocationPathPlanLabAction(),
            WeatherWidgetPathPlanLabAction(),
            MusicLibraryPathPlanLabAction(),
            BooksPathPlanePlanLabAction(),
            PodcastsPathPlanePlanLabAction(),
            TvAppPathPlanePlanLabAction(),
            HomekitPathPlanePlanLabAction(),
            HealthPathPlanePlanLabAction(),
            WalletPassPathPlanLabAction(),
            FindmyPathPlanePlanLabAction(),
            ShortcutsIcloudSyncPlanLabAction(),
            DevicemanagementProfilePlanLabAction(),
            SoftwareupdateCatalogPlanLabAction(),
        ]
    }

    public func action(id: String) -> (any Action)? {
        actions.first { type(of: $0).id == id }
    }

    public var actionIds: [String] {
        actions.map { type(of: $0).id }.sorted()
    }
}

/// Example lab action that only succeeds with full consent and dry-run awareness.
public struct NoopLabAction: Action {
    public static let id = "lab.noop"
    public static let consent = ConsentPolicy(
        requiresAuthorizedFlag: true,
        requiresScope: true,
        requiresOperator: true,
        requiresConfirmToken: "lab.noop"
    )

    public init() {}

    public func run(context: EvaluationContext) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        return ActionResult(
            actionId: Self.id,
            success: true,
            message: context.dryRun
                ? "Dry-run: would execute noop lab action"
                : "Noop lab action executed (no host changes)",
            dryRun: context.dryRun,
            plannedSteps: context.dryRun
                ? ["Validate consent tokens", "No filesystem changes"]
                : ["Validate consent tokens", "No-op complete"],
            cleanupNotes: ["Nothing to clean up"],
            artifacts: []
        )
    }
}
