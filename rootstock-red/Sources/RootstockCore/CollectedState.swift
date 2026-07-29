/// Versioned host snapshot filled by collectors and ranked by vectors/checks (path/meta only).
import Foundation

/// Versioned host snapshot produced by collectors.
public struct CollectedState: Codable, Sendable, Equatable {
    public var schemaVersion: String = RootstockCore.schemaVersion
    public var collectedAt: Date = Date()
    public var host: HostState? = nil
    public var securityProducts: [SecurityProductHit] = []
    public var launchAgents: [LaunchAgentEntry] = []
    public var systemLaunchAgents: [LaunchAgentEntry] = []
    public var launchDaemons: [LaunchAgentEntry] = []
    public var btmStorePresent: Bool? = nil
    public var loginItemPaths: [String] = []
    public var loginItems: LoginItemsState? = nil
    public var browserMeta: [BrowserMetaEntry] = []
    public var codesignSamples: [CodesignSample] = []
    public var dylibRiskHits: [DylibRiskHit] = []
    public var injectabilityHits: [InjectabilityHit] = []
    public var systemExtensionPaths: [String] = []
    public var privilegedHelperTools: [String] = []
    public var tcc: TCCState? = nil
    public var credPaths: [CredPathHit] = []
    public var loobins: [LOOBinHit] = []
    /// Ranked LOOBin plans (discovery / persist / execute) from LOLPlanner.
    public var lolPlans: [LOLPlanEntry] = []
    public var runningApps: [RunningAppInfo] = []
    public var mdm: MDMState? = nil
    public var identity: IdentityState? = nil
    public var protections: ProtectionsState? = nil
    public var network: NetworkState? = nil
    /// Endpoint Security / EDR sensor posture.
    public var esf: ESFPostureState? = nil
    /// OS patch-debt / CVE suggester context.
    public var patchDebt: PatchDebtState? = nil
    /// Launch-constraint injectability truth.
    public var launchConstraints: LaunchConstraintState? = nil
    /// NetworkExtension / VPN / content-filter posture.
    public var networkExtension: NetworkExtensionState? = nil
    /// Authorization rights / auth.db / PackageKit surface.
    public var authRights: AuthRightsState? = nil
    /// Developer toolchain dual-use surface.
    public var developerToolchain: DeveloperToolchainState? = nil
    /// Time Machine / local snapshot data-access surface.
    public var timeMachine: TimeMachineState? = nil
    /// User-writable mobileconfig / profile sideload risk.
    public var configProfileSideload: ConfigProfileSideloadState? = nil
    /// App sandbox / entitlement thick-client surface.
    public var appSandboxEntitlements: AppSandboxEntitlementState? = nil
    /// Notarization / stapling trust depth.
    public var notarizationStapling: NotarizationStaplingState? = nil
    /// Virtualization / container dual-use surface.
    public var virtualizationContainers: VirtualizationContainerState? = nil
    /// Continuity / AirDrop proximity posture.
    public var continuityAirDrop: ContinuityAirDropState? = nil
    /// FileVault / recovery escrow posture.
    public var fileVaultEscrow: FileVaultEscrowState? = nil
    /// ClickFix / paste-and-run Terminal delivery posture.
    public var clickFixTerminalDelivery: ClickFixTerminalDeliveryState? = nil
    /// Remote Apple Events / EPPC lateral posture.
    public var remoteAppleEvents: RemoteAppleEventsState? = nil
    /// Spotlight / mdworker / on-device AI-cache data-access.
    public var spotlightAICache: SpotlightAICacheState? = nil
    /// Security-product management-plane unload class.
    public var securityMgmtPlane: SecurityMgmtPlaneState? = nil
    /// Third-party TCC inheritance / embedded interpreter.
    public var thirdPartyTCCInheritance: ThirdPartyTCCInheritanceState? = nil
    /// SSH-agent / key path lateral depth.
    public var sshAgentKeyPath: SSHAgentKeyPathState? = nil
    /// PackageKit installer design-based persistence.
    public var packageKitInstallerDesign: PackageKitInstallerDesignState? = nil
    /// Archive / quarantine third-party extractor.
    public var archiveQuarantineExtractor: ArchiveQuarantineExtractorState? = nil
    /// Info-stealer multi-app collection path plane.
    public var infoStealerPathPlane: InfoStealerPathPlaneState? = nil
    /// TCC / ESF visibility-depth posture.
    public var tccEsfVisibilityDepth: TCCESFVisibilityDepthState? = nil
    /// MDM profile shallow parse depth.
    public var mdmProfileParseDepth: MDMProfileParseDepthState? = nil
    /// Custom URL scheme / document-handler surface.
    public var urlSchemeHandler: URLSchemeHandlerState? = nil
    /// Launchd disabled / override depth.
    public var launchdOverrideDepth: LaunchdOverrideDepthState? = nil
    /// Browser extension dual-use plane.
    public var browserExtensionDualUse: BrowserExtensionDualUseState? = nil
    /// Shortcuts / App Intents automation lateral.
    public var shortcutsAppIntents: ShortcutsAppIntentsState? = nil
    /// Webloc / Internet Location file delivery.
    public var weblocInetlocDelivery: WeblocInetlocDeliveryState? = nil
    /// Mail rules / Apple Mail automation persistence.
    public var mailRulesAutomation: MailRulesAutomationState? = nil
    /// Unified log / logarchive observation depth.
    public var unifiedLogObservation: UnifiedLogObservationState? = nil
    /// Dock persistent apps / recent items dual-use.
    public var dockPersistenceSurface: DockPersistenceSurfaceState? = nil
    /// Compiled AppleScript / OSA delivery residual.
    public var osascriptScptDelivery: OsascriptScptDeliveryState? = nil
    /// Network share / SMB mount dual-use lateral.
    public var networkShareMount: NetworkShareMountState? = nil
    /// Calendar / Reminders automation lateral surface.
    public var calendarRemindersAutomation: CalendarRemindersAutomationState? = nil
    /// Gatekeeper assessment / syspolicyd history depth.
    public var gatekeeperAssessmentHistory: GatekeeperAssessmentHistoryState? = nil
    /// Homebrew / third-party package manager dual-use.
    public var homebrewPackageDualUse: HomebrewPackageDualUseState? = nil
    /// CUPS / printer dual-use residual surface.
    public var cupsPrintDualUse: CupsPrintDualUseState? = nil
    /// ScreenCapture / screenshot privacy dual-use depth.
    public var screenCapturePrivacyDualUse: ScreenCapturePrivacyDualUseState? = nil
    /// Automator workflow delivery residual.
    public var automatorWorkflow: AutomatorWorkflowState? = nil
    /// iCloud Drive / Mobile Documents path plane.
    public var icloudDrivePath: IcloudDrivePathState? = nil
    /// Bluetooth / Continuity proximity residual depth.
    public var bluetoothContinuityDepth: BluetoothContinuityDepthState? = nil
    /// Font validation / ATS dual-use surface.
    public var fontValidationDualuse: FontValidationDualuseState? = nil
    /// QuickLook thumbnail cache residual depth.
    public var quicklookCacheDepth: QuicklookCacheDepthState? = nil
    /// DNS resolver / mDNSResponder dual-use surface.
    public var dnsResolverDualuse: DnsResolverDualuseState? = nil
    /// LaunchServices QuarantineEvents DB residual depth.
    public var lsQuarantineDbDepth: LsQuarantineDbDepthState? = nil
    /// PAM authentication module residual surface.
    public var pamAuthModule: PamAuthModuleState? = nil
    /// Cron / at job dual-use residual depth.
    public var cronAtJobDepth: CronAtJobDepthState? = nil
    /// Notes.app metadata collection path plane.
    public var notesMetadataPlane: NotesMetadataPlaneState? = nil
    /// Photos.app library collection path plane.
    public var photosLibraryPath: PhotosLibraryPathState? = nil
    /// VPN configuration dual-use residual surface.
    public var vpnConfigDualuse: VpnConfigDualuseState? = nil
    /// App sandbox container residual depth.
    public var sandboxContainerDepth: SandboxContainerDepthState? = nil
    /// XPC Mach service residual depth.
    public var xpcMachServiceDepth: XpcMachServiceDepthState? = nil
    /// Time Machine local snapshot residual depth.
    public var tmLocalSnapshotDepth: TmLocalSnapshotDepthState? = nil
    /// Emond legacy rules residual depth.
    public var emondLegacyDepth: EmondLegacyDepthState? = nil
    /// Screen Sharing / ARD residual depth.
    public var screenSharingArdDepth: ScreenSharingArdDepthState? = nil
    /// Keychain ACL path residual surface.
    public var keychainAclPath: KeychainAclPathState? = nil
    /// Python runtime dual-use residual surface.
    public var pythonRuntimeDualuse: PythonRuntimeDualuseState? = nil
    /// Shell plugin manager dual-use residual.
    public var shellPluginManager: ShellPluginManagerState? = nil
    /// AirPlay receiver dual-use residual.
    public var airplayReceiverSurface: AirplayReceiverSurfaceState? = nil
    /// Handoff / Universal Clipboard residual depth.
    public var handoffClipboardDepth: HandoffClipboardDepthState? = nil
    /// iMessage / Messages path collection plane.
    public var imessagePathPlane: ImessagePathPlaneState? = nil
    /// FaceTime / camera pipeline dual-use surface.
    public var facetimeCameraSurface: FacetimeCameraSurfaceState? = nil
    /// Finder Sync extension dual-use surface.
    public var finderSyncExtension: FinderSyncExtensionState? = nil
    /// File Provider domain residual surface.
    public var fileproviderDomain: FileproviderDomainState? = nil
    /// Notification Center residual depth.
    public var notificationCenterDepth: NotificationCenterDepthState? = nil
    /// Siri / Suggestions data-access residual.
    public var siriSuggestionsPlane: SiriSuggestionsPlaneState? = nil
    /// Spotlight importer residual depth.
    public var spotlightImporterDepth: SpotlightImporterDepthState? = nil
    /// Contacts database path residual plane.
    public var contactsPathPlane: ContactsPathPlaneState? = nil
    /// Calendar server / CalDAV residual surface.
    public var calendarServerPath: CalendarServerPathState? = nil
    /// Reminders cloud path residual plane.
    public var remindersCloudPath: RemindersCloudPathState? = nil
    /// Maps / location services residual plane.
    public var mapsLocationPath: MapsLocationPathState? = nil
    /// Weather / widget data residual plane.
    public var weatherWidgetPath: WeatherWidgetPathState? = nil
    /// Music / media library path residual.
    public var musicLibraryPath: MusicLibraryPathState? = nil
    /// Books / EPUB path residual plane.
    public var booksPathPlane: BooksPathPlaneState? = nil
    /// Podcasts library path residual.
    public var podcastsPathPlane: PodcastsPathPlaneState? = nil
    /// TV.app residual path plane.
    public var tvAppPathPlane: TvAppPathPlaneState? = nil
    /// HomeKit residual path plane.
    public var homekitPathPlane: HomekitPathPlaneState? = nil
    /// Health app residual path plane.
    public var healthPathPlane: HealthPathPlaneState? = nil
    /// Wallet / pass residual path plane.
    public var walletPassPath: WalletPassPathState? = nil
    /// Find My residual path plane.
    public var findmyPathPlane: FindmyPathPlaneState? = nil
    /// Shortcuts iCloud sync residual depth.
    public var shortcutsIcloudSync: ShortcutsIcloudSyncState? = nil
    /// Device management profile residual depth.
    public var devicemanagementProfile: DevicemanagementProfileState? = nil
    /// Software Update catalog residual surface.
    public var softwareupdateCatalog: SoftwareupdateCatalogState? = nil
    public var collectorNotes: [String: String] = [:]
    public var deniedCollectors: [String] = []

}
