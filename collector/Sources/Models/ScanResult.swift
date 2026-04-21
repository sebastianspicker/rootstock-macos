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

    public init(
        scanId: String,
        timestamp: String,
        hostname: String,
        macosVersion: String,
        collectorVersion: String,
        elevation: ElevationInfo,
        applications: [Application],
        tccGrants: [TCCGrant],
        xpcServices: [XPCService],
        keychainAcls: [KeychainItem],
        mdmProfiles: [MDMProfile],
        launchItems: [LaunchItem],
        localGroups: [LocalGroup] = [],
        remoteAccessServices: [RemoteAccessService] = [],
        firewallStatus: [FirewallStatus] = [],
        loginSessions: [LoginSession] = [],
        authorizationRights: [AuthorizationRight] = [],
        authorizationPlugins: [AuthorizationPlugin] = [],
        systemExtensions: [SystemExtension] = [],
        sudoersRules: [SudoersRule] = [],
        runningProcesses: [RunningProcess] = [],
        userDetails: [UserDetail] = [],
        fileAcls: [FileACL] = [],
        bluetoothDevices: [BluetoothDevice] = [],
        adBinding: ADBinding? = nil,
        kerberosArtifacts: [KerberosArtifact] = [],
        sandboxProfiles: [SandboxProfile] = [],
        gatekeeperEnabled: Bool? = nil,
        sipEnabled: Bool? = nil,
        filevaultEnabled: Bool? = nil,
        lockdownModeEnabled: Bool? = nil,
        bluetoothEnabled: Bool? = nil,
        bluetoothDiscoverable: Bool? = nil,
        screenLockEnabled: Bool? = nil,
        screenLockDelay: Int? = nil,
        displaySleepTimeout: Int? = nil,
        thunderboltSecurityLevel: String? = nil,
        secureBootLevel: String? = nil,
        externalBootAllowed: Bool? = nil,
        icloudSignedIn: Bool? = nil,
        icloudDriveEnabled: Bool? = nil,
        icloudKeychainEnabled: Bool? = nil,
        errors: [CollectionError]
    ) {
        self.scanId = scanId
        self.timestamp = timestamp
        self.hostname = hostname
        self.macosVersion = macosVersion
        self.collectorVersion = collectorVersion
        self.elevation = elevation
        self.applications = applications
        self.tccGrants = tccGrants
        self.xpcServices = xpcServices
        self.keychainAcls = keychainAcls
        self.mdmProfiles = mdmProfiles
        self.launchItems = launchItems
        self.localGroups = localGroups
        self.remoteAccessServices = remoteAccessServices
        self.firewallStatus = firewallStatus
        self.loginSessions = loginSessions
        self.authorizationRights = authorizationRights
        self.authorizationPlugins = authorizationPlugins
        self.systemExtensions = systemExtensions
        self.sudoersRules = sudoersRules
        self.runningProcesses = runningProcesses
        self.userDetails = userDetails
        self.fileAcls = fileAcls
        self.bluetoothDevices = bluetoothDevices
        self.adBinding = adBinding
        self.kerberosArtifacts = kerberosArtifacts
        self.sandboxProfiles = sandboxProfiles
        self.gatekeeperEnabled = gatekeeperEnabled
        self.sipEnabled = sipEnabled
        self.filevaultEnabled = filevaultEnabled
        self.lockdownModeEnabled = lockdownModeEnabled
        self.bluetoothEnabled = bluetoothEnabled
        self.bluetoothDiscoverable = bluetoothDiscoverable
        self.screenLockEnabled = screenLockEnabled
        self.screenLockDelay = screenLockDelay
        self.displaySleepTimeout = displaySleepTimeout
        self.thunderboltSecurityLevel = thunderboltSecurityLevel
        self.secureBootLevel = secureBootLevel
        self.externalBootAllowed = externalBootAllowed
        self.icloudSignedIn = icloudSignedIn
        self.icloudDriveEnabled = icloudDriveEnabled
        self.icloudKeychainEnabled = icloudKeychainEnabled
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
