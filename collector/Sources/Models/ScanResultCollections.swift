import Foundation

extension ScanResult {
    public struct InventoryCollections: Codable, Sendable {
        public let networkListeners: [NetworkListener]
        public let certificateTrustSettings: [TrustedCertificate]
        public let browserExtensions: [BrowserExtension]
        public let installedPackages: [InstalledPackage]

        public init(
            networkListeners: [NetworkListener] = [],
            certificateTrustSettings: [TrustedCertificate] = [],
            browserExtensions: [BrowserExtension] = [],
            installedPackages: [InstalledPackage] = []
        ) {
            self.networkListeners = networkListeners
            self.certificateTrustSettings = certificateTrustSettings
            self.browserExtensions = browserExtensions
            self.installedPackages = installedPackages
        }
    }

    public struct HostPosture: Codable, Sendable {
        public let gatekeeperEnabled: Bool?
        public let lockdownModeEnabled: Bool?
        public let icloudSignedIn: Bool?
        public let sipEnabled: Bool?
        public let bluetoothEnabled: Bool?
        public let icloudDriveEnabled: Bool?
        public let filevaultEnabled: Bool?
        public let bluetoothDiscoverable: Bool?
        public let icloudKeychainEnabled: Bool?
        public let screenLockEnabled: Bool?
        public let thunderboltSecurityLevel: String?
        public let screenLockDelay: Int?
        public let secureBootLevel: String?
        public let displaySleepTimeout: Int?
        public let externalBootAllowed: Bool?
        public let hostSecuritySettings: HostSecuritySettings?
        public let networkConfiguration: NetworkConfiguration?

        public init(
            gatekeeperEnabled: Bool? = nil,
            sipEnabled: Bool? = nil,
            filevaultEnabled: Bool? = nil,
            physicalSecurity: PhysicalSecurity = PhysicalSecurity(),
            icloud: ICloud = ICloud(),
            hostSecuritySettings: HostSecuritySettings? = nil,
            networkConfiguration: NetworkConfiguration? = nil
        ) {
            self.gatekeeperEnabled = gatekeeperEnabled
            self.lockdownModeEnabled = physicalSecurity.lockdownModeEnabled
            self.icloudSignedIn = icloud.icloudSignedIn
            self.sipEnabled = sipEnabled
            self.bluetoothEnabled = physicalSecurity.bluetoothEnabled
            self.icloudDriveEnabled = icloud.icloudDriveEnabled
            self.filevaultEnabled = filevaultEnabled
            self.bluetoothDiscoverable = physicalSecurity.bluetoothDiscoverable
            self.icloudKeychainEnabled = icloud.icloudKeychainEnabled
            self.screenLockEnabled = physicalSecurity.screenLockEnabled
            self.thunderboltSecurityLevel = physicalSecurity.thunderboltSecurityLevel
            self.screenLockDelay = physicalSecurity.screenLockDelay
            self.secureBootLevel = physicalSecurity.secureBootLevel
            self.displaySleepTimeout = physicalSecurity.displaySleepTimeout
            self.externalBootAllowed = physicalSecurity.externalBootAllowed
            self.hostSecuritySettings = hostSecuritySettings
            self.networkConfiguration = networkConfiguration
        }
    }
}
