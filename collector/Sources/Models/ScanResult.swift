import Foundation

/// Privilege context under which the collector ran.
public struct ElevationInfo: Codable, Sendable {
    public let isRoot: Bool
    public let hasFda: Bool

    public init(isRoot: Bool, hasFda: Bool) {
        self.isRoot = isRoot
        self.hasFda = hasFda
    }

    enum CodingKeys: String, CodingKey {
        case isRoot = "is_root"
        case hasFda = "has_fda"
    }
}

/// Top-level output of a collector scan, containing all discovered metadata and errors.
public struct ScanResult: Codable, Sendable {
    public let scanId: String
    public let timestamp: String
    public let hostname: String
    public let macosVersion: String
    public let collectorVersion: String
    public let elevation: ElevationInfo
    public let applications: [Application]
    public let tccGrants: [TCCGrant]
    public let xpcServices: [XPCService]
    public let keychainAcls: [KeychainItem]
    public let mdmProfiles: [MDMProfile]
    public let launchItems: [LaunchItem]
    public let localGroups: [LocalGroup]
    public let remoteAccessServices: [RemoteAccessService]
    public let firewallStatus: [FirewallStatus]
    public let loginSessions: [LoginSession]
    public let authorizationRights: [AuthorizationRight]
    public let authorizationPlugins: [AuthorizationPlugin]
    public let systemExtensions: [SystemExtension]
    public let sudoersRules: [SudoersRule]
    public let runningProcesses: [RunningProcess]
    public let userDetails: [UserDetail]
    public let fileAcls: [FileACL]
    public let bluetoothDevices: [BluetoothDevice]
    public let adBinding: ADBinding?
    public let kerberosArtifacts: [KerberosArtifact]
    public let sandboxProfiles: [SandboxProfile]
    public let gatekeeperEnabled: Bool?
    public let sipEnabled: Bool?
    public let filevaultEnabled: Bool?
    public let lockdownModeEnabled: Bool?
    public let bluetoothEnabled: Bool?
    public let bluetoothDiscoverable: Bool?
    public let screenLockEnabled: Bool?
    public let screenLockDelay: Int?
    public let displaySleepTimeout: Int?
    public let thunderboltSecurityLevel: String?
    public let secureBootLevel: String?
    public let externalBootAllowed: Bool?
    public let icloudSignedIn: Bool?
    public let icloudDriveEnabled: Bool?
    public let icloudKeychainEnabled: Bool?
    public let errors: [CollectionError]

    public struct Metadata: Codable, Sendable {
        public let scanId: String
        public let timestamp: String
        public let hostname: String
        public let macosVersion: String
        public let collectorVersion: String

        public init(
            scanId: String,
            timestamp: String,
            hostname: String,
            macosVersion: String,
            collectorVersion: String
        ) {
            self.scanId = scanId
            self.timestamp = timestamp
            self.hostname = hostname
            self.macosVersion = macosVersion
            self.collectorVersion = collectorVersion
        }
    }

    public struct Collections: Codable, Sendable {
        public let applications: [Application]
        public let tccGrants: [TCCGrant]
        public let xpcServices: [XPCService]
        public let keychainAcls: [KeychainItem]
        public let mdmProfiles: [MDMProfile]
        public let launchItems: [LaunchItem]
        public let localGroups: [LocalGroup]
        public let remoteAccessServices: [RemoteAccessService]
        public let firewallStatus: [FirewallStatus]
        public let loginSessions: [LoginSession]
        public let authorizationRights: [AuthorizationRight]
        public let authorizationPlugins: [AuthorizationPlugin]
        public let systemExtensions: [SystemExtension]
        public let sudoersRules: [SudoersRule]
        public let runningProcesses: [RunningProcess]
        public let userDetails: [UserDetail]
        public let fileAcls: [FileACL]
        public let bluetoothDevices: [BluetoothDevice]
        public let adBinding: ADBinding?
        public let kerberosArtifacts: [KerberosArtifact]
        public let sandboxProfiles: [SandboxProfile]

        public init(
            core: CoreCollections = CoreCollections(),
            accountAccess: AccountAccessCollections = AccountAccessCollections(),
            system: SystemCollections = SystemCollections()
        ) {
            self.applications = core.applications
            self.tccGrants = core.tccGrants
            self.xpcServices = core.xpcServices
            self.keychainAcls = core.keychainAcls
            self.mdmProfiles = core.mdmProfiles
            self.launchItems = core.launchItems
            self.localGroups = accountAccess.localGroups
            self.remoteAccessServices = accountAccess.remoteAccessServices
            self.firewallStatus = accountAccess.firewallStatus
            self.loginSessions = accountAccess.loginSessions
            self.authorizationRights = accountAccess.authorizationRights
            self.authorizationPlugins = accountAccess.authorizationPlugins
            self.systemExtensions = accountAccess.systemExtensions
            self.sudoersRules = accountAccess.sudoersRules
            self.runningProcesses = system.runningProcesses
            self.userDetails = system.userDetails
            self.fileAcls = system.fileAcls
            self.bluetoothDevices = system.bluetoothDevices
            self.adBinding = system.adBinding
            self.kerberosArtifacts = system.kerberosArtifacts
            self.sandboxProfiles = system.sandboxProfiles
        }
    }

    public struct CoreCollections: Codable, Sendable {
        public let applications: [Application]
        public let tccGrants: [TCCGrant]
        public let xpcServices: [XPCService]
        public let keychainAcls: [KeychainItem]
        public let mdmProfiles: [MDMProfile]
        public let launchItems: [LaunchItem]

        public init(
            applications: [Application] = [],
            tccGrants: [TCCGrant] = [],
            xpcServices: [XPCService] = [],
            keychainAcls: [KeychainItem] = [],
            mdmProfiles: [MDMProfile] = [],
            launchItems: [LaunchItem] = []
        ) {
            self.applications = applications
            self.tccGrants = tccGrants
            self.xpcServices = xpcServices
            self.keychainAcls = keychainAcls
            self.mdmProfiles = mdmProfiles
            self.launchItems = launchItems
        }
    }

    public struct AccountAccessCollections: Codable, Sendable {
        public let localGroups: [LocalGroup]
        public let remoteAccessServices: [RemoteAccessService]
        public let firewallStatus: [FirewallStatus]
        public let loginSessions: [LoginSession]
        public let authorizationRights: [AuthorizationRight]
        public let authorizationPlugins: [AuthorizationPlugin]
        public let systemExtensions: [SystemExtension]
        public let sudoersRules: [SudoersRule]

        public init(
            localGroups: [LocalGroup] = [],
            remoteAccessServices: [RemoteAccessService] = [],
            firewallStatus: [FirewallStatus] = [],
            loginSessions: [LoginSession] = [],
            authorization: AuthorizationCollections = AuthorizationCollections(),
            sudoersRules: [SudoersRule] = []
        ) {
            self.localGroups = localGroups
            self.remoteAccessServices = remoteAccessServices
            self.firewallStatus = firewallStatus
            self.loginSessions = loginSessions
            self.authorizationRights = authorization.authorizationRights
            self.authorizationPlugins = authorization.authorizationPlugins
            self.systemExtensions = authorization.systemExtensions
            self.sudoersRules = sudoersRules
        }
    }

    public struct AuthorizationCollections: Codable, Sendable {
        public let authorizationRights: [AuthorizationRight]
        public let authorizationPlugins: [AuthorizationPlugin]
        public let systemExtensions: [SystemExtension]

        public init(
            authorizationRights: [AuthorizationRight] = [],
            authorizationPlugins: [AuthorizationPlugin] = [],
            systemExtensions: [SystemExtension] = []
        ) {
            self.authorizationRights = authorizationRights
            self.authorizationPlugins = authorizationPlugins
            self.systemExtensions = systemExtensions
        }
    }

    public struct SystemCollections: Codable, Sendable {
        public let runningProcesses: [RunningProcess]
        public let userDetails: [UserDetail]
        public let fileAcls: [FileACL]
        public let bluetoothDevices: [BluetoothDevice]
        public let adBinding: ADBinding?
        public let kerberosArtifacts: [KerberosArtifact]
        public let sandboxProfiles: [SandboxProfile]

        public init(
            runningProcesses: [RunningProcess] = [],
            userDetails: [UserDetail] = [],
            fileAcls: [FileACL] = [],
            bluetoothDevices: [BluetoothDevice] = [],
            adBinding: ADBinding? = nil,
            kerberosArtifacts: [KerberosArtifact] = [],
            sandboxProfiles: [SandboxProfile] = []
        ) {
            self.runningProcesses = runningProcesses
            self.userDetails = userDetails
            self.fileAcls = fileAcls
            self.bluetoothDevices = bluetoothDevices
            self.adBinding = adBinding
            self.kerberosArtifacts = kerberosArtifacts
            self.sandboxProfiles = sandboxProfiles
        }
    }

    public struct HostPosture: Codable, Sendable {
        public let gatekeeperEnabled: Bool?
        public let sipEnabled: Bool?
        public let filevaultEnabled: Bool?
        public let lockdownModeEnabled: Bool?
        public let bluetoothEnabled: Bool?
        public let bluetoothDiscoverable: Bool?
        public let screenLockEnabled: Bool?
        public let screenLockDelay: Int?
        public let displaySleepTimeout: Int?
        public let thunderboltSecurityLevel: String?
        public let secureBootLevel: String?
        public let externalBootAllowed: Bool?
        public let icloudSignedIn: Bool?
        public let icloudDriveEnabled: Bool?
        public let icloudKeychainEnabled: Bool?

        public init(
            gatekeeperEnabled: Bool? = nil,
            sipEnabled: Bool? = nil,
            filevaultEnabled: Bool? = nil,
            physicalSecurity: PhysicalSecurity = PhysicalSecurity(),
            icloud: ICloud = ICloud()
        ) {
            self.gatekeeperEnabled = gatekeeperEnabled
            self.sipEnabled = sipEnabled
            self.filevaultEnabled = filevaultEnabled
            self.lockdownModeEnabled = physicalSecurity.lockdownModeEnabled
            self.bluetoothEnabled = physicalSecurity.bluetoothEnabled
            self.bluetoothDiscoverable = physicalSecurity.bluetoothDiscoverable
            self.screenLockEnabled = physicalSecurity.screenLockEnabled
            self.screenLockDelay = physicalSecurity.screenLockDelay
            self.displaySleepTimeout = physicalSecurity.displaySleepTimeout
            self.thunderboltSecurityLevel = physicalSecurity.thunderboltSecurityLevel
            self.secureBootLevel = physicalSecurity.secureBootLevel
            self.externalBootAllowed = physicalSecurity.externalBootAllowed
            self.icloudSignedIn = icloud.icloudSignedIn
            self.icloudDriveEnabled = icloud.icloudDriveEnabled
            self.icloudKeychainEnabled = icloud.icloudKeychainEnabled
        }
    }

    public struct PhysicalSecurity: Codable, Sendable {
        public let lockdownModeEnabled: Bool?
        public let bluetoothEnabled: Bool?
        public let bluetoothDiscoverable: Bool?
        public let screenLockEnabled: Bool?
        public let screenLockDelay: Int?
        public let displaySleepTimeout: Int?
        public let thunderboltSecurityLevel: String?
        public let secureBootLevel: String?
        public let externalBootAllowed: Bool?

        public init(
            device: DeviceSecurity = DeviceSecurity(),
            screen: ScreenSecurity = ScreenSecurity(),
            boot: BootSecurity = BootSecurity()
        ) {
            self.lockdownModeEnabled = device.lockdownModeEnabled
            self.bluetoothEnabled = device.bluetoothEnabled
            self.bluetoothDiscoverable = device.bluetoothDiscoverable
            self.screenLockEnabled = screen.screenLockEnabled
            self.screenLockDelay = screen.screenLockDelay
            self.displaySleepTimeout = screen.displaySleepTimeout
            self.thunderboltSecurityLevel = boot.thunderboltSecurityLevel
            self.secureBootLevel = boot.secureBootLevel
            self.externalBootAllowed = boot.externalBootAllowed
        }
    }

    public struct DeviceSecurity: Codable, Sendable {
        public let lockdownModeEnabled: Bool?
        public let bluetoothEnabled: Bool?
        public let bluetoothDiscoverable: Bool?

        public init(
            lockdownModeEnabled: Bool? = nil,
            bluetoothEnabled: Bool? = nil,
            bluetoothDiscoverable: Bool? = nil
        ) {
            self.lockdownModeEnabled = lockdownModeEnabled
            self.bluetoothEnabled = bluetoothEnabled
            self.bluetoothDiscoverable = bluetoothDiscoverable
        }
    }

    public struct ScreenSecurity: Codable, Sendable {
        public let screenLockEnabled: Bool?
        public let screenLockDelay: Int?
        public let displaySleepTimeout: Int?

        public init(
            screenLockEnabled: Bool? = nil,
            screenLockDelay: Int? = nil,
            displaySleepTimeout: Int? = nil
        ) {
            self.screenLockEnabled = screenLockEnabled
            self.screenLockDelay = screenLockDelay
            self.displaySleepTimeout = displaySleepTimeout
        }
    }

    public struct BootSecurity: Codable, Sendable {
        public let thunderboltSecurityLevel: String?
        public let secureBootLevel: String?
        public let externalBootAllowed: Bool?

        public init(
            thunderboltSecurityLevel: String? = nil,
            secureBootLevel: String? = nil,
            externalBootAllowed: Bool? = nil
        ) {
            self.thunderboltSecurityLevel = thunderboltSecurityLevel
            self.secureBootLevel = secureBootLevel
            self.externalBootAllowed = externalBootAllowed
        }
    }

    public struct ICloud: Codable, Sendable {
        public let icloudSignedIn: Bool?
        public let icloudDriveEnabled: Bool?
        public let icloudKeychainEnabled: Bool?

        public init(
            icloudSignedIn: Bool? = nil,
            icloudDriveEnabled: Bool? = nil,
            icloudKeychainEnabled: Bool? = nil
        ) {
            self.icloudSignedIn = icloudSignedIn
            self.icloudDriveEnabled = icloudDriveEnabled
            self.icloudKeychainEnabled = icloudKeychainEnabled
        }
    }

    public init(
        metadata: Metadata,
        elevation: ElevationInfo,
        collections: Collections = Collections(),
        hostPosture: HostPosture = HostPosture(),
        errors: [CollectionError]
    ) {
        (self.scanId, self.timestamp) = (metadata.scanId, metadata.timestamp)
        (self.hostname, self.macosVersion) = (metadata.hostname, metadata.macosVersion)
        self.collectorVersion = metadata.collectorVersion
        self.elevation = elevation
        self.applications = collections.applications
        self.tccGrants = collections.tccGrants
        self.xpcServices = collections.xpcServices
        self.keychainAcls = collections.keychainAcls
        self.mdmProfiles = collections.mdmProfiles
        self.launchItems = collections.launchItems
        self.localGroups = collections.localGroups
        self.remoteAccessServices = collections.remoteAccessServices
        self.firewallStatus = collections.firewallStatus
        self.loginSessions = collections.loginSessions
        self.authorizationRights = collections.authorizationRights
        self.authorizationPlugins = collections.authorizationPlugins
        self.systemExtensions = collections.systemExtensions
        self.sudoersRules = collections.sudoersRules
        self.runningProcesses = collections.runningProcesses
        self.userDetails = collections.userDetails
        self.fileAcls = collections.fileAcls
        self.bluetoothDevices = collections.bluetoothDevices
        self.adBinding = collections.adBinding
        self.kerberosArtifacts = collections.kerberosArtifacts
        self.sandboxProfiles = collections.sandboxProfiles
        self.gatekeeperEnabled = hostPosture.gatekeeperEnabled
        self.sipEnabled = hostPosture.sipEnabled
        self.filevaultEnabled = hostPosture.filevaultEnabled
        self.lockdownModeEnabled = hostPosture.lockdownModeEnabled
        self.bluetoothEnabled = hostPosture.bluetoothEnabled
        self.bluetoothDiscoverable = hostPosture.bluetoothDiscoverable
        self.screenLockEnabled = hostPosture.screenLockEnabled
        self.screenLockDelay = hostPosture.screenLockDelay
        self.displaySleepTimeout = hostPosture.displaySleepTimeout
        self.thunderboltSecurityLevel = hostPosture.thunderboltSecurityLevel
        self.secureBootLevel = hostPosture.secureBootLevel
        self.externalBootAllowed = hostPosture.externalBootAllowed
        self.icloudSignedIn = hostPosture.icloudSignedIn
        self.icloudDriveEnabled = hostPosture.icloudDriveEnabled
        self.icloudKeychainEnabled = hostPosture.icloudKeychainEnabled
        self.errors = errors
    }

    enum CodingKeys: String, CodingKey {
        case scanId = "scan_id"
        case timestamp
        case hostname
        case macosVersion = "macos_version"
        case collectorVersion = "collector_version"
        case elevation
        case applications
        case tccGrants = "tcc_grants"
        case xpcServices = "xpc_services"
        case keychainAcls = "keychain_acls"
        case mdmProfiles = "mdm_profiles"
        case launchItems = "launch_items"
        case localGroups = "local_groups"
        case remoteAccessServices = "remote_access_services"
        case firewallStatus = "firewall_status"
        case loginSessions = "login_sessions"
        case authorizationRights = "authorization_rights"
        case authorizationPlugins = "authorization_plugins"
        case systemExtensions = "system_extensions"
        case sudoersRules = "sudoers_rules"
        case runningProcesses = "running_processes"
        case userDetails = "user_details"
        case fileAcls = "file_acls"
        case bluetoothDevices = "bluetooth_devices"
        case adBinding = "ad_binding"
        case kerberosArtifacts = "kerberos_artifacts"
        case sandboxProfiles = "sandbox_profiles"
        case gatekeeperEnabled = "gatekeeper_enabled"
        case sipEnabled = "sip_enabled"
        case filevaultEnabled = "filevault_enabled"
        case lockdownModeEnabled = "lockdown_mode_enabled"
        case bluetoothEnabled = "bluetooth_enabled"
        case bluetoothDiscoverable = "bluetooth_discoverable"
        case screenLockEnabled = "screen_lock_enabled"
        case screenLockDelay = "screen_lock_delay"
        case displaySleepTimeout = "display_sleep_timeout"
        case thunderboltSecurityLevel = "thunderbolt_security_level"
        case secureBootLevel = "secure_boot_level"
        case externalBootAllowed = "external_boot_allowed"
        case icloudSignedIn = "icloud_signed_in"
        case icloudDriveEnabled = "icloud_drive_enabled"
        case icloudKeychainEnabled = "icloud_keychain_enabled"
        case errors
    }
}
