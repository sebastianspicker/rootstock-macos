import Foundation
import Models

extension ScanOrchestrator {
    func makeScanResult(
        applications: [Application], modules: ScanModuleCollection,
        hostPosture: HostPostureCollection, errors: [CollectionError]
    ) -> ScanResult {
        ScanResult(
            metadata: makeMetadata(),
            elevation: ElevationInfo(isRoot: getuid() == 0, hasFda: detectFDA()),
            collections: makeCollections(applications: applications, modules: modules),
            hostPosture: makeHostPosture(from: hostPosture, modules: modules),
            errors: errors
        )
    }

    func makeMetadata() -> ScanResult.Metadata {
        ScanResult.Metadata(
            scanId: UUID().uuidString,
            timestamp: ISO8601DateFormatter().string(from: Date()),
            hostname: ProcessInfo.processInfo.hostName,
            hardwareUUID: HardwareIdentity.detect(),
            macosVersion: ProcessInfo.processInfo.operatingSystemVersionString,
            collectorVersion: RootstockCommand.collectorVersion
        )
    }

    func makeCollections(
        applications: [Application],
        modules: ScanModuleCollection
    ) -> ScanResult.Collections {
        ScanResult.Collections(
            core: makeCoreCollections(applications: applications, modules: modules),
            accountAccess: makeAccountAccessCollections(modules),
            system: makeSystemCollections(applications: applications, modules: modules),
            inventory: modules.inventory
        )
    }

    func makeCoreCollections(
        applications: [Application],
        modules: ScanModuleCollection
    ) -> ScanResult.CoreCollections {
        ScanResult.CoreCollections(
            applications: applications,
            tccGrants: modules.tccGrants,
            xpcServices: modules.xpcServices,
            keychainAcls: modules.keychainAcls,
            mdmProfiles: modules.mdmProfiles,
            launchItems: modules.launchItems
        )
    }

    func makeAccountAccessCollections(
        _ modules: ScanModuleCollection
    ) -> ScanResult.AccountAccessCollections {
        ScanResult.AccountAccessCollections(
            localGroups: modules.groupCollection.localGroups + modules.activeDirectory.localGroups,
            remoteAccessServices: modules.remoteAccessServices,
            firewallStatus: modules.firewallStatus,
            loginSessions: modules.loginSessions,
            authorization: ScanResult.AuthorizationCollections(
                authorizationRights: modules.authorizationRights,
                authorizationPlugins: modules.authorizationPlugins,
                systemExtensions: modules.systemExtensions
            ),
            sudoersRules: modules.sudoersRules
        )
    }

    func makeSystemCollections(
        applications: [Application],
        modules: ScanModuleCollection
    ) -> ScanResult.SystemCollections {
        ScanResult.SystemCollections(
            runningProcesses: modules.runningProcesses,
            userDetails: modules.groupCollection.userDetails + modules.activeDirectory.userDetails,
            fileAcls: modules.fileAcls,
            bluetoothDevices: modules.physicalSecurity.bluetoothDevices,
            adBinding: modules.activeDirectory.binding,
            kerberosArtifacts: modules.kerberosArtifacts,
            sandboxProfiles: applications.compactMap(\.sandboxProfile)
        )
    }

    func makeHostPosture(
        from hostPosture: HostPostureCollection,
        modules: ScanModuleCollection
    ) -> ScanResult.HostPosture {
        ScanResult.HostPosture(
            gatekeeperEnabled: hostPosture.gatekeeperEnabled,
            sipEnabled: hostPosture.sipEnabled,
            filevaultEnabled: hostPosture.filevaultEnabled,
            physicalSecurity: makePhysicalSecurity(from: modules.physicalSecurity),
            icloud: ScanResult.ICloud(
                icloudSignedIn: hostPosture.icloudSignedIn,
                icloudDriveEnabled: hostPosture.icloudDriveEnabled,
                icloudKeychainEnabled: hostPosture.icloudKeychainEnabled
            ),
            hostSecuritySettings: hostPosture.hostSecuritySettings,
            networkConfiguration: hostPosture.networkConfiguration
        )
    }

    func makePhysicalSecurity(
        from physicalSecurity: PhysicalSecurityCollection
    ) -> ScanResult.PhysicalSecurity {
        ScanResult.PhysicalSecurity(
            device: ScanResult.DeviceSecurity(
                lockdownModeEnabled: physicalSecurity.lockdownModeEnabled,
                bluetoothEnabled: physicalSecurity.bluetoothEnabled,
                bluetoothDiscoverable: physicalSecurity.bluetoothDiscoverable
            ),
            screen: ScanResult.ScreenSecurity(
                screenLockEnabled: physicalSecurity.screenLockEnabled,
                screenLockDelay: physicalSecurity.screenLockDelay,
                displaySleepTimeout: physicalSecurity.displaySleepTimeout
            ),
            boot: ScanResult.BootSecurity(
                thunderboltSecurityLevel: physicalSecurity.thunderboltSecurityLevel,
                secureBootLevel: physicalSecurity.secureBootLevel,
                externalBootAllowed: physicalSecurity.externalBootAllowed
            )
        )
    }
}
