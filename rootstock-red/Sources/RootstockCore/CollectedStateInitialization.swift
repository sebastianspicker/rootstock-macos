import Foundation

extension CollectedState {
    public struct FoundationInput: Sendable {
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

        public init() {}
    }

    public struct PostureInput: Sendable {
        public var credPaths: [CredPathHit] = []
        public var loobins: [LOOBinHit] = []
        public var lolPlans: [LOLPlanEntry] = []
        public var runningApps: [RunningAppInfo] = []
        public var mdm: MDMState? = nil
        public var identity: IdentityState? = nil
        public var protections: ProtectionsState? = nil
        public var network: NetworkState? = nil
        public var esf: ESFPostureState? = nil
        public var patchDebt: PatchDebtState? = nil
        public var launchConstraints: LaunchConstraintState? = nil
        public var networkExtension: NetworkExtensionState? = nil
        public var authRights: AuthRightsState? = nil
        public var developerToolchain: DeveloperToolchainState? = nil
        public var timeMachine: TimeMachineState? = nil
        public var configProfileSideload: ConfigProfileSideloadState? = nil
        public var appSandboxEntitlements: AppSandboxEntitlementState? = nil
        public var notarizationStapling: NotarizationStaplingState? = nil
        public var virtualizationContainers: VirtualizationContainerState? = nil
        public var continuityAirDrop: ContinuityAirDropState? = nil
        public var fileVaultEscrow: FileVaultEscrowState? = nil
        public var clickFixTerminalDelivery: ClickFixTerminalDeliveryState? = nil
        public var remoteAppleEvents: RemoteAppleEventsState? = nil
        public var spotlightAICache: SpotlightAICacheState? = nil
        public var securityMgmtPlane: SecurityMgmtPlaneState? = nil
        public var thirdPartyTCCInheritance: ThirdPartyTCCInheritanceState? = nil
        public var sshAgentKeyPath: SSHAgentKeyPathState? = nil
        public var packageKitInstallerDesign: PackageKitInstallerDesignState? = nil
        public var archiveQuarantineExtractor: ArchiveQuarantineExtractorState? = nil
        public var infoStealerPathPlane: InfoStealerPathPlaneState? = nil
        public var tccEsfVisibilityDepth: TCCESFVisibilityDepthState? = nil
        public var mdmProfileParseDepth: MDMProfileParseDepthState? = nil

        public init() {}
    }

    public struct AutomationPlanesInput: Sendable {
        public var urlSchemeHandler: URLSchemeHandlerState? = nil
        public var launchdOverrideDepth: LaunchdOverrideDepthState? = nil
        public var browserExtensionDualUse: BrowserExtensionDualUseState? = nil
        public var shortcutsAppIntents: ShortcutsAppIntentsState? = nil
        public var weblocInetlocDelivery: WeblocInetlocDeliveryState? = nil
        public var mailRulesAutomation: MailRulesAutomationState? = nil
        public var unifiedLogObservation: UnifiedLogObservationState? = nil
        public var dockPersistenceSurface: DockPersistenceSurfaceState? = nil
        public var osascriptScptDelivery: OsascriptScptDeliveryState? = nil
        public var networkShareMount: NetworkShareMountState? = nil
        public var calendarRemindersAutomation: CalendarRemindersAutomationState? = nil
        public var gatekeeperAssessmentHistory: GatekeeperAssessmentHistoryState? = nil
        public var homebrewPackageDualUse: HomebrewPackageDualUseState? = nil
        public var cupsPrintDualUse: CupsPrintDualUseState? = nil
        public var screenCapturePrivacyDualUse: ScreenCapturePrivacyDualUseState? = nil
        public var automatorWorkflow: AutomatorWorkflowState? = nil
        public var icloudDrivePath: IcloudDrivePathState? = nil
        public var bluetoothContinuityDepth: BluetoothContinuityDepthState? = nil
        public var fontValidationDualuse: FontValidationDualuseState? = nil
        public var quicklookCacheDepth: QuicklookCacheDepthState? = nil
        public var dnsResolverDualuse: DnsResolverDualuseState? = nil
        public var lsQuarantineDbDepth: LsQuarantineDbDepthState? = nil
        public var pamAuthModule: PamAuthModuleState? = nil
        public var cronAtJobDepth: CronAtJobDepthState? = nil
        public var notesMetadataPlane: NotesMetadataPlaneState? = nil

        public init() {}
    }

    public struct ResidualPlanesInput: Sendable {
        public var photosLibraryPath: PhotosLibraryPathState? = nil
        public var vpnConfigDualuse: VpnConfigDualuseState? = nil
        public var sandboxContainerDepth: SandboxContainerDepthState? = nil
        public var xpcMachServiceDepth: XpcMachServiceDepthState? = nil
        public var tmLocalSnapshotDepth: TmLocalSnapshotDepthState? = nil
        public var emondLegacyDepth: EmondLegacyDepthState? = nil
        public var screenSharingArdDepth: ScreenSharingArdDepthState? = nil
        public var keychainAclPath: KeychainAclPathState? = nil
        public var pythonRuntimeDualuse: PythonRuntimeDualuseState? = nil
        public var shellPluginManager: ShellPluginManagerState? = nil
        public var airplayReceiverSurface: AirplayReceiverSurfaceState? = nil
        public var handoffClipboardDepth: HandoffClipboardDepthState? = nil
        public var imessagePathPlane: ImessagePathPlaneState? = nil
        public var facetimeCameraSurface: FacetimeCameraSurfaceState? = nil
        public var finderSyncExtension: FinderSyncExtensionState? = nil
        public var fileproviderDomain: FileproviderDomainState? = nil
        public var notificationCenterDepth: NotificationCenterDepthState? = nil
        public var siriSuggestionsPlane: SiriSuggestionsPlaneState? = nil
        public var spotlightImporterDepth: SpotlightImporterDepthState? = nil
        public var contactsPathPlane: ContactsPathPlaneState? = nil
        public var calendarServerPath: CalendarServerPathState? = nil
        public var remindersCloudPath: RemindersCloudPathState? = nil
        public var mapsLocationPath: MapsLocationPathState? = nil
        public var weatherWidgetPath: WeatherWidgetPathState? = nil
        public var musicLibraryPath: MusicLibraryPathState? = nil
        public var booksPathPlane: BooksPathPlaneState? = nil
        public var podcastsPathPlane: PodcastsPathPlaneState? = nil
        public var tvAppPathPlane: TvAppPathPlaneState? = nil
        public var homekitPathPlane: HomekitPathPlaneState? = nil
        public var healthPathPlane: HealthPathPlaneState? = nil
        public var walletPassPath: WalletPassPathState? = nil
        public var findmyPathPlane: FindmyPathPlaneState? = nil
        public var shortcutsIcloudSync: ShortcutsIcloudSyncState? = nil
        public var devicemanagementProfile: DevicemanagementProfileState? = nil
        public var softwareupdateCatalog: SoftwareupdateCatalogState? = nil

        public init() {}
    }

    public struct CollectionInput: Sendable {
        public var collectorNotes: [String: String] = [:]
        public var deniedCollectors: [String] = []

        public init() {}
    }

    private init(empty: Void) {}

    public init(
        foundation: FoundationInput = .init(),
        posture: PostureInput = .init(),
        automationPlanes: AutomationPlanesInput = .init(),
        residualPlanes: ResidualPlanesInput = .init(),
        collection: CollectionInput = .init()
    ) {
        self.init(empty: ())
        apply(foundation)
        apply(posture)
        apply(automationPlanes)
        apply(residualPlanes)
        apply(collection)
    }

    private mutating func apply(_ input: FoundationInput) {
        self.schemaVersion = input.schemaVersion
        self.collectedAt = input.collectedAt
        self.host = input.host
        self.securityProducts = input.securityProducts
        self.launchAgents = input.launchAgents
        self.systemLaunchAgents = input.systemLaunchAgents
        self.launchDaemons = input.launchDaemons
        self.btmStorePresent = input.btmStorePresent
        self.loginItemPaths = input.loginItemPaths
        self.loginItems = input.loginItems
        self.browserMeta = input.browserMeta
        self.codesignSamples = input.codesignSamples
        self.dylibRiskHits = input.dylibRiskHits
        self.injectabilityHits = input.injectabilityHits
        self.systemExtensionPaths = input.systemExtensionPaths
        self.privilegedHelperTools = input.privilegedHelperTools
        self.tcc = input.tcc
    }

    private mutating func apply(_ input: PostureInput) {
        self.credPaths = input.credPaths
        self.loobins = input.loobins
        self.lolPlans = input.lolPlans
        self.runningApps = input.runningApps
        self.mdm = input.mdm
        self.identity = input.identity
        self.protections = input.protections
        self.network = input.network
        self.esf = input.esf
        self.patchDebt = input.patchDebt
        self.launchConstraints = input.launchConstraints
        self.networkExtension = input.networkExtension
        self.authRights = input.authRights
        self.developerToolchain = input.developerToolchain
        self.timeMachine = input.timeMachine
        self.configProfileSideload = input.configProfileSideload
        self.appSandboxEntitlements = input.appSandboxEntitlements
        self.notarizationStapling = input.notarizationStapling
        self.virtualizationContainers = input.virtualizationContainers
        self.continuityAirDrop = input.continuityAirDrop
        self.fileVaultEscrow = input.fileVaultEscrow
        self.clickFixTerminalDelivery = input.clickFixTerminalDelivery
        self.remoteAppleEvents = input.remoteAppleEvents
        self.spotlightAICache = input.spotlightAICache
        self.securityMgmtPlane = input.securityMgmtPlane
        self.thirdPartyTCCInheritance = input.thirdPartyTCCInheritance
        self.sshAgentKeyPath = input.sshAgentKeyPath
        self.packageKitInstallerDesign = input.packageKitInstallerDesign
        self.archiveQuarantineExtractor = input.archiveQuarantineExtractor
        self.infoStealerPathPlane = input.infoStealerPathPlane
        self.tccEsfVisibilityDepth = input.tccEsfVisibilityDepth
        self.mdmProfileParseDepth = input.mdmProfileParseDepth
    }

    private mutating func apply(_ input: AutomationPlanesInput) {
        self.urlSchemeHandler = input.urlSchemeHandler
        self.launchdOverrideDepth = input.launchdOverrideDepth
        self.browserExtensionDualUse = input.browserExtensionDualUse
        self.shortcutsAppIntents = input.shortcutsAppIntents
        self.weblocInetlocDelivery = input.weblocInetlocDelivery
        self.mailRulesAutomation = input.mailRulesAutomation
        self.unifiedLogObservation = input.unifiedLogObservation
        self.dockPersistenceSurface = input.dockPersistenceSurface
        self.osascriptScptDelivery = input.osascriptScptDelivery
        self.networkShareMount = input.networkShareMount
        self.calendarRemindersAutomation = input.calendarRemindersAutomation
        self.gatekeeperAssessmentHistory = input.gatekeeperAssessmentHistory
        self.homebrewPackageDualUse = input.homebrewPackageDualUse
        self.cupsPrintDualUse = input.cupsPrintDualUse
        self.screenCapturePrivacyDualUse = input.screenCapturePrivacyDualUse
        self.automatorWorkflow = input.automatorWorkflow
        self.icloudDrivePath = input.icloudDrivePath
        self.bluetoothContinuityDepth = input.bluetoothContinuityDepth
        self.fontValidationDualuse = input.fontValidationDualuse
        self.quicklookCacheDepth = input.quicklookCacheDepth
        self.dnsResolverDualuse = input.dnsResolverDualuse
        self.lsQuarantineDbDepth = input.lsQuarantineDbDepth
        self.pamAuthModule = input.pamAuthModule
        self.cronAtJobDepth = input.cronAtJobDepth
        self.notesMetadataPlane = input.notesMetadataPlane
    }

    private mutating func apply(_ input: ResidualPlanesInput) {
        self.photosLibraryPath = input.photosLibraryPath
        self.vpnConfigDualuse = input.vpnConfigDualuse
        self.sandboxContainerDepth = input.sandboxContainerDepth
        self.xpcMachServiceDepth = input.xpcMachServiceDepth
        self.tmLocalSnapshotDepth = input.tmLocalSnapshotDepth
        self.emondLegacyDepth = input.emondLegacyDepth
        self.screenSharingArdDepth = input.screenSharingArdDepth
        self.keychainAclPath = input.keychainAclPath
        self.pythonRuntimeDualuse = input.pythonRuntimeDualuse
        self.shellPluginManager = input.shellPluginManager
        self.airplayReceiverSurface = input.airplayReceiverSurface
        self.handoffClipboardDepth = input.handoffClipboardDepth
        self.imessagePathPlane = input.imessagePathPlane
        self.facetimeCameraSurface = input.facetimeCameraSurface
        self.finderSyncExtension = input.finderSyncExtension
        self.fileproviderDomain = input.fileproviderDomain
        self.notificationCenterDepth = input.notificationCenterDepth
        self.siriSuggestionsPlane = input.siriSuggestionsPlane
        self.spotlightImporterDepth = input.spotlightImporterDepth
        self.contactsPathPlane = input.contactsPathPlane
        self.calendarServerPath = input.calendarServerPath
        self.remindersCloudPath = input.remindersCloudPath
        self.mapsLocationPath = input.mapsLocationPath
        self.weatherWidgetPath = input.weatherWidgetPath
        self.musicLibraryPath = input.musicLibraryPath
        self.booksPathPlane = input.booksPathPlane
        self.podcastsPathPlane = input.podcastsPathPlane
        self.tvAppPathPlane = input.tvAppPathPlane
        self.homekitPathPlane = input.homekitPathPlane
        self.healthPathPlane = input.healthPathPlane
        self.walletPassPath = input.walletPassPath
        self.findmyPathPlane = input.findmyPathPlane
        self.shortcutsIcloudSync = input.shortcutsIcloudSync
        self.devicemanagementProfile = input.devicemanagementProfile
        self.softwareupdateCatalog = input.softwareupdateCatalog
    }

    private mutating func apply(_ input: CollectionInput) {
        self.collectorNotes = input.collectorNotes
        self.deniedCollectors = input.deniedCollectors
    }

}
