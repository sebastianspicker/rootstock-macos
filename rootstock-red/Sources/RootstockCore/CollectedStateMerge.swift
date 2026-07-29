import Foundation

extension CollectedState {
    /// Merge non-nil sections from another state (later wins for scalars).
    public mutating func merge(_ other: CollectedState) {
        mergeFoundation(from: other)
        mergePosture(from: other)
        mergeAutomationPlanes(from: other)
        mergeResidualPlanes(from: other)
        mergeCollection(from: other)
    }

    private mutating func mergeFoundation(from other: CollectedState) {
        mergeFoundationPart1(from: other)
        mergeFoundationPart2(from: other)
        mergeFoundationPart3(from: other)
    }

    private mutating func mergeFoundationPart1(from other: CollectedState) {
        if let host = other.host { self.host = host }
        if !other.securityProducts.isEmpty { self.securityProducts = other.securityProducts }
        if !other.launchAgents.isEmpty { self.launchAgents = other.launchAgents }
        if !other.systemLaunchAgents.isEmpty { self.systemLaunchAgents = other.systemLaunchAgents }
        if !other.launchDaemons.isEmpty { self.launchDaemons = other.launchDaemons }
        if let btm = other.btmStorePresent { self.btmStorePresent = btm }
        if !other.loginItemPaths.isEmpty { self.loginItemPaths = other.loginItemPaths }
    }

    private mutating func mergeFoundationPart2(from other: CollectedState) {
        if let loginItems = other.loginItems { self.loginItems = loginItems }
        if !other.browserMeta.isEmpty { self.browserMeta = other.browserMeta }
        if !other.codesignSamples.isEmpty { self.codesignSamples = other.codesignSamples }
        if !other.dylibRiskHits.isEmpty { self.dylibRiskHits = other.dylibRiskHits }
        if !other.injectabilityHits.isEmpty { self.injectabilityHits = other.injectabilityHits }
        if !other.systemExtensionPaths.isEmpty { self.systemExtensionPaths = other.systemExtensionPaths }
        if !other.privilegedHelperTools.isEmpty { self.privilegedHelperTools = other.privilegedHelperTools }
    }

    private mutating func mergeFoundationPart3(from other: CollectedState) {
        if let tcc = other.tcc {
            if var existing = self.tcc {
                if tcc.fullDiskAccessLikely != nil {
                    existing.fullDiskAccessLikely = tcc.fullDiskAccessLikely
                }
                if tcc.probeMethod != "stub" { existing.probeMethod = tcc.probeMethod }
                existing.notes.append(contentsOf: tcc.notes)
                let mergedSignals = Array(Set(existing.domainSignals + tcc.domainSignals)).sorted()
                existing.domainSignals = mergedSignals
                self.tcc = existing
            } else {
                self.tcc = tcc
            }
        }
    }

    private mutating func mergePosture(from other: CollectedState) {
        mergePosturePart1(from: other)
        mergePosturePart2(from: other)
        mergePosturePart3(from: other)
        mergePosturePart4(from: other)
        mergePosturePart5(from: other)
    }

    private mutating func mergePosturePart1(from other: CollectedState) {
        if !other.credPaths.isEmpty { self.credPaths = other.credPaths }
        if !other.loobins.isEmpty { self.loobins = other.loobins }
        if !other.lolPlans.isEmpty { self.lolPlans = other.lolPlans }
        if !other.runningApps.isEmpty { self.runningApps = other.runningApps }
        if let mdm = other.mdm { self.mdm = mdm }
        if let identity = other.identity { self.identity = identity }
        if let protections = other.protections { self.protections = protections }
    }

    private mutating func mergePosturePart2(from other: CollectedState) {
        if let network = other.network { self.network = network }
        if let esf = other.esf { self.esf = esf }
        if let patchDebt = other.patchDebt { self.patchDebt = patchDebt }
        if let launchConstraints = other.launchConstraints {
            self.launchConstraints = launchConstraints
        }
        if let networkExtension = other.networkExtension {
            self.networkExtension = networkExtension
        }
        if let authRights = other.authRights { self.authRights = authRights }
        if let developerToolchain = other.developerToolchain {
            self.developerToolchain = developerToolchain
        }
    }

    private mutating func mergePosturePart3(from other: CollectedState) {
        if let timeMachine = other.timeMachine { self.timeMachine = timeMachine }
        if let configProfileSideload = other.configProfileSideload {
            self.configProfileSideload = configProfileSideload
        }
        if let appSandboxEntitlements = other.appSandboxEntitlements {
            self.appSandboxEntitlements = appSandboxEntitlements
        }
        if let notarizationStapling = other.notarizationStapling {
            self.notarizationStapling = notarizationStapling
        }
        if let virtualizationContainers = other.virtualizationContainers {
            self.virtualizationContainers = virtualizationContainers
        }
        if let continuityAirDrop = other.continuityAirDrop {
            self.continuityAirDrop = continuityAirDrop
        }
        if let fileVaultEscrow = other.fileVaultEscrow {
            self.fileVaultEscrow = fileVaultEscrow
        }
    }

    private mutating func mergePosturePart4(from other: CollectedState) {
        if let clickFixTerminalDelivery = other.clickFixTerminalDelivery {
            self.clickFixTerminalDelivery = clickFixTerminalDelivery
        }
        if let remoteAppleEvents = other.remoteAppleEvents {
            self.remoteAppleEvents = remoteAppleEvents
        }
        if let spotlightAICache = other.spotlightAICache {
            self.spotlightAICache = spotlightAICache
        }
        if let securityMgmtPlane = other.securityMgmtPlane {
            self.securityMgmtPlane = securityMgmtPlane
        }
        if let thirdPartyTCCInheritance = other.thirdPartyTCCInheritance {
            self.thirdPartyTCCInheritance = thirdPartyTCCInheritance
        }
        if let sshAgentKeyPath = other.sshAgentKeyPath {
            self.sshAgentKeyPath = sshAgentKeyPath
        }
        if let packageKitInstallerDesign = other.packageKitInstallerDesign {
            self.packageKitInstallerDesign = packageKitInstallerDesign
        }
    }

    private mutating func mergePosturePart5(from other: CollectedState) {
        if let archiveQuarantineExtractor = other.archiveQuarantineExtractor {
            self.archiveQuarantineExtractor = archiveQuarantineExtractor
        }
        if let infoStealerPathPlane = other.infoStealerPathPlane {
            self.infoStealerPathPlane = infoStealerPathPlane
        }
        if let tccEsfVisibilityDepth = other.tccEsfVisibilityDepth {
            self.tccEsfVisibilityDepth = tccEsfVisibilityDepth
        }
        if let mdmProfileParseDepth = other.mdmProfileParseDepth {
            self.mdmProfileParseDepth = mdmProfileParseDepth
        }
    }

    private mutating func mergeAutomationPlanes(from other: CollectedState) {
        mergeAutomationPlanesPart1(from: other)
        mergeAutomationPlanesPart2(from: other)
        mergeAutomationPlanesPart3(from: other)
        mergeAutomationPlanesPart4(from: other)
    }

    private mutating func mergeAutomationPlanesPart1(from other: CollectedState) {
        if let urlSchemeHandler = other.urlSchemeHandler {
            self.urlSchemeHandler = urlSchemeHandler
        }
        if let launchdOverrideDepth = other.launchdOverrideDepth {
            self.launchdOverrideDepth = launchdOverrideDepth
        }
        if let browserExtensionDualUse = other.browserExtensionDualUse {
            self.browserExtensionDualUse = browserExtensionDualUse
        }
        if let shortcutsAppIntents = other.shortcutsAppIntents {
            self.shortcutsAppIntents = shortcutsAppIntents
        }
        if let weblocInetlocDelivery = other.weblocInetlocDelivery {
            self.weblocInetlocDelivery = weblocInetlocDelivery
        }
        if let mailRulesAutomation = other.mailRulesAutomation {
            self.mailRulesAutomation = mailRulesAutomation
        }
        if let unifiedLogObservation = other.unifiedLogObservation {
            self.unifiedLogObservation = unifiedLogObservation
        }
    }

    private mutating func mergeAutomationPlanesPart2(from other: CollectedState) {
        if let dockPersistenceSurface = other.dockPersistenceSurface {
            self.dockPersistenceSurface = dockPersistenceSurface
        }
        if let osascriptScptDelivery = other.osascriptScptDelivery {
            self.osascriptScptDelivery = osascriptScptDelivery
        }
        if let networkShareMount = other.networkShareMount {
            self.networkShareMount = networkShareMount
        }
        if let calendarRemindersAutomation = other.calendarRemindersAutomation {
            self.calendarRemindersAutomation = calendarRemindersAutomation
        }
        if let gatekeeperAssessmentHistory = other.gatekeeperAssessmentHistory {
            self.gatekeeperAssessmentHistory = gatekeeperAssessmentHistory
        }
        if let homebrewPackageDualUse = other.homebrewPackageDualUse {
            self.homebrewPackageDualUse = homebrewPackageDualUse
        }
        if let cupsPrintDualUse = other.cupsPrintDualUse {
            self.cupsPrintDualUse = cupsPrintDualUse
        }
    }

    private mutating func mergeAutomationPlanesPart3(from other: CollectedState) {
        if let screenCapturePrivacyDualUse = other.screenCapturePrivacyDualUse {
            self.screenCapturePrivacyDualUse = screenCapturePrivacyDualUse
        }
        if let automatorWorkflow = other.automatorWorkflow {
            self.automatorWorkflow = automatorWorkflow
        }
        if let icloudDrivePath = other.icloudDrivePath {
            self.icloudDrivePath = icloudDrivePath
        }
        if let bluetoothContinuityDepth = other.bluetoothContinuityDepth {
            self.bluetoothContinuityDepth = bluetoothContinuityDepth
        }
        if let fontValidationDualuse = other.fontValidationDualuse {
            self.fontValidationDualuse = fontValidationDualuse
        }
        if let quicklookCacheDepth = other.quicklookCacheDepth {
            self.quicklookCacheDepth = quicklookCacheDepth
        }
        if let dnsResolverDualuse = other.dnsResolverDualuse {
            self.dnsResolverDualuse = dnsResolverDualuse
        }
    }

    private mutating func mergeAutomationPlanesPart4(from other: CollectedState) {
        if let lsQuarantineDbDepth = other.lsQuarantineDbDepth {
            self.lsQuarantineDbDepth = lsQuarantineDbDepth
        }
        if let pamAuthModule = other.pamAuthModule {
            self.pamAuthModule = pamAuthModule
        }
        if let cronAtJobDepth = other.cronAtJobDepth {
            self.cronAtJobDepth = cronAtJobDepth
        }
        if let notesMetadataPlane = other.notesMetadataPlane {
            self.notesMetadataPlane = notesMetadataPlane
        }
    }

    private mutating func mergeResidualPlanes(from other: CollectedState) {
        mergeResidualPlanesPart1(from: other)
        mergeResidualPlanesPart2(from: other)
        mergeResidualPlanesPart3(from: other)
        mergeResidualPlanesPart4(from: other)
        mergeResidualPlanesPart5(from: other)
    }

    private mutating func mergeResidualPlanesPart1(from other: CollectedState) {
        if let photosLibraryPath = other.photosLibraryPath {
            self.photosLibraryPath = photosLibraryPath
        }
        if let vpnConfigDualuse = other.vpnConfigDualuse {
            self.vpnConfigDualuse = vpnConfigDualuse
        }
        if let sandboxContainerDepth = other.sandboxContainerDepth {
            self.sandboxContainerDepth = sandboxContainerDepth
        }
        if let xpcMachServiceDepth = other.xpcMachServiceDepth {
            self.xpcMachServiceDepth = xpcMachServiceDepth
        }
        if let tmLocalSnapshotDepth = other.tmLocalSnapshotDepth {
            self.tmLocalSnapshotDepth = tmLocalSnapshotDepth
        }
        if let emondLegacyDepth = other.emondLegacyDepth {
            self.emondLegacyDepth = emondLegacyDepth
        }
        if let screenSharingArdDepth = other.screenSharingArdDepth {
            self.screenSharingArdDepth = screenSharingArdDepth
        }
    }

    private mutating func mergeResidualPlanesPart2(from other: CollectedState) {
        if let keychainAclPath = other.keychainAclPath {
            self.keychainAclPath = keychainAclPath
        }
        if let pythonRuntimeDualuse = other.pythonRuntimeDualuse {
            self.pythonRuntimeDualuse = pythonRuntimeDualuse
        }
        if let shellPluginManager = other.shellPluginManager {
            self.shellPluginManager = shellPluginManager
        }
        if let airplayReceiverSurface = other.airplayReceiverSurface {
            self.airplayReceiverSurface = airplayReceiverSurface
        }
        if let handoffClipboardDepth = other.handoffClipboardDepth {
            self.handoffClipboardDepth = handoffClipboardDepth
        }
        if let imessagePathPlane = other.imessagePathPlane {
            self.imessagePathPlane = imessagePathPlane
        }
        if let facetimeCameraSurface = other.facetimeCameraSurface {
            self.facetimeCameraSurface = facetimeCameraSurface
        }
    }

    private mutating func mergeResidualPlanesPart3(from other: CollectedState) {
        if let finderSyncExtension = other.finderSyncExtension {
            self.finderSyncExtension = finderSyncExtension
        }
        if let fileproviderDomain = other.fileproviderDomain {
            self.fileproviderDomain = fileproviderDomain
        }
        if let notificationCenterDepth = other.notificationCenterDepth {
            self.notificationCenterDepth = notificationCenterDepth
        }
        if let siriSuggestionsPlane = other.siriSuggestionsPlane {
            self.siriSuggestionsPlane = siriSuggestionsPlane
        }
        if let spotlightImporterDepth = other.spotlightImporterDepth {
            self.spotlightImporterDepth = spotlightImporterDepth
        }
        if let contactsPathPlane = other.contactsPathPlane {
            self.contactsPathPlane = contactsPathPlane
        }
        if let calendarServerPath = other.calendarServerPath {
            self.calendarServerPath = calendarServerPath
        }
    }

    private mutating func mergeResidualPlanesPart4(from other: CollectedState) {
        if let remindersCloudPath = other.remindersCloudPath {
            self.remindersCloudPath = remindersCloudPath
        }
        if let mapsLocationPath = other.mapsLocationPath {
            self.mapsLocationPath = mapsLocationPath
        }
        if let weatherWidgetPath = other.weatherWidgetPath {
            self.weatherWidgetPath = weatherWidgetPath
        }
        if let musicLibraryPath = other.musicLibraryPath {
            self.musicLibraryPath = musicLibraryPath
        }
        if let booksPathPlane = other.booksPathPlane {
            self.booksPathPlane = booksPathPlane
        }
        if let podcastsPathPlane = other.podcastsPathPlane {
            self.podcastsPathPlane = podcastsPathPlane
        }
        if let tvAppPathPlane = other.tvAppPathPlane {
            self.tvAppPathPlane = tvAppPathPlane
        }
    }

    private mutating func mergeResidualPlanesPart5(from other: CollectedState) {
        if let homekitPathPlane = other.homekitPathPlane {
            self.homekitPathPlane = homekitPathPlane
        }
        if let healthPathPlane = other.healthPathPlane {
            self.healthPathPlane = healthPathPlane
        }
        if let walletPassPath = other.walletPassPath {
            self.walletPassPath = walletPassPath
        }
        if let findmyPathPlane = other.findmyPathPlane {
            self.findmyPathPlane = findmyPathPlane
        }
        if let shortcutsIcloudSync = other.shortcutsIcloudSync {
            self.shortcutsIcloudSync = shortcutsIcloudSync
        }
        if let devicemanagementProfile = other.devicemanagementProfile {
            self.devicemanagementProfile = devicemanagementProfile
        }
        if let softwareupdateCatalog = other.softwareupdateCatalog {
            self.softwareupdateCatalog = softwareupdateCatalog
        }
    }

    private mutating func mergeCollection(from other: CollectedState) {
        for (k, v) in other.collectorNotes { self.collectorNotes[k] = v }
        self.deniedCollectors.append(contentsOf: other.deniedCollectors)
    }
}
