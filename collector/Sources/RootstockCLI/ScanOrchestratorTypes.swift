import Models
import PhysicalSecurity

extension ScanOrchestrator {
    struct ApplicationCollection {
        let applications: [Application]
        let errors: [CollectionError]
    }

    struct GroupCollection {
        var localGroups: [LocalGroup] = []
        var userDetails: [UserDetail] = []
    }

    struct ActiveDirectoryCollection {
        var binding: ADBinding?
        var userDetails: [UserDetail] = []
        var localGroups: [LocalGroup] = []
    }

    struct HostPostureCollection {
        let gatekeeperEnabled: Bool?
        let sipEnabled: Bool?
        let filevaultEnabled: Bool?
        let icloudSignedIn: Bool?
        let icloudDriveEnabled: Bool?
        let icloudKeychainEnabled: Bool?
    }

    struct HostProbeResult {
        let value: Bool?
        let error: CollectionError?
    }

    struct ICloudProbeResult {
        let signedIn: Bool?
        let driveEnabled: Bool?
        let keychainEnabled: Bool?
        let error: CollectionError?
    }

    struct HostPostureProbeResults {
        let gatekeeper: HostProbeResult
        let sip: HostProbeResult
        let filevault: HostProbeResult
        let icloud: ICloudProbeResult
    }

    /// Typed, normalized module output before it is assembled into `ScanResult`.
    struct ScanModuleCollection {
        let tccGrants: [TCCGrant]
        let xpcServices: [XPCService]
        let keychainAcls: [KeychainItem]
        let mdmProfiles: [MDMProfile]
        let launchItems: [LaunchItem]
        let groupCollection: GroupCollection
        let remoteAccessServices: [RemoteAccessService]
        let firewallStatus: [FirewallStatus]
        let loginSessions: [LoginSession]
        let authorizationRights: [AuthorizationRight]
        let authorizationPlugins: [AuthorizationPlugin]
        let systemExtensions: [SystemExtension]
        let sudoersRules: [SudoersRule]
        let runningProcesses: [RunningProcess]
        let fileAcls: [FileACL]
        let physicalSecurity: PhysicalSecurityCollection
        let activeDirectory: ActiveDirectoryCollection
        let kerberosArtifacts: [KerberosArtifact]
    }

    typealias TimedDataSourceResult = (DataSourceResult, Double)
    typealias TimedPhysicalSecurityResult = (PhysicalSecurityResult, Double)
    typealias TimedActiveDirectoryResult = (
        (result: DataSourceResult, binding: ADBinding?),
        Double
    )

    /// Concurrent collector results keyed by stable module ID, never task order.
    struct ModuleTaskResults {
        let dataSourceResults: [RootstockModuleID: TimedDataSourceResult]
        let physicalSecurity: TimedPhysicalSecurityResult?
        let activeDirectory: TimedActiveDirectoryResult?

        func result(for module: RootstockModuleID) -> TimedDataSourceResult? {
            dataSourceResults[module]
        }
    }

    /// Bridges the multi-payload physical posture probe into the scan schema.
    struct PhysicalSecurityCollection {
        var bluetoothDevices: [BluetoothDevice] = []
        var lockdownModeEnabled: Bool?
        var bluetoothEnabled: Bool?
        var bluetoothDiscoverable: Bool?
        var screenLockEnabled: Bool?
        var screenLockDelay: Int?
        var displaySleepTimeout: Int?
        var thunderboltSecurityLevel: String?
        var secureBootLevel: String?
        var externalBootAllowed: Bool?
    }
}
