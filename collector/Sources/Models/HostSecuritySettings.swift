import Foundation

/// Host-wide account, remote administration, update, and malware-protection settings.
public struct HostSecuritySettings: Codable, Sendable {
    /// `GuestEnabled` from the system loginwindow preferences.
    public let guestAccountEnabled: Bool?

    /// `autoLoginUser` from the system loginwindow preferences (nil when absent).
    public let autoLoginUser: String?

    /// Whether the root account has an enabled authentication authority.
    public let rootAccountEnabled: Bool?

    /// Whether the Remote Apple Events service (`com.apple.AEServer`) is loaded.
    public let remoteAppleEventsEnabled: Bool?

    /// Whether the Remote Management agent (`com.apple.RemoteDesktop.agent`) is loaded.
    public let remoteManagementEnabled: Bool?

    /// Software Update automation settings.
    public let softwareUpdate: SoftwareUpdateSettings?

    /// XProtect bundle version.
    public let xprotectVersion: String?

    /// XProtect Remediator version.
    public let xprotectRemediatorVersion: String?

    /// Malware Removal Tool version.
    public let mrtVersion: String?

    /// Login and account settings.
    public struct Accounts: Codable, Sendable {
        public let guestAccountEnabled: Bool?
        public let autoLoginUser: String?
        public let rootAccountEnabled: Bool?

        public init(
            guestAccountEnabled: Bool? = nil,
            autoLoginUser: String? = nil,
            rootAccountEnabled: Bool? = nil
        ) {
            self.guestAccountEnabled = guestAccountEnabled
            self.autoLoginUser = autoLoginUser
            self.rootAccountEnabled = rootAccountEnabled
        }
    }

    /// Built-in malware-protection component versions.
    public struct MalwareProtection: Codable, Sendable {
        public let xprotectVersion: String?
        public let xprotectRemediatorVersion: String?
        public let mrtVersion: String?

        public init(
            xprotectVersion: String? = nil,
            xprotectRemediatorVersion: String? = nil,
            mrtVersion: String? = nil
        ) {
            self.xprotectVersion = xprotectVersion
            self.xprotectRemediatorVersion = xprotectRemediatorVersion
            self.mrtVersion = mrtVersion
        }
    }

    public init(
        accounts: Accounts = Accounts(),
        remoteAppleEventsEnabled: Bool? = nil,
        remoteManagementEnabled: Bool? = nil,
        softwareUpdate: SoftwareUpdateSettings? = nil,
        malwareProtection: MalwareProtection = MalwareProtection()
    ) {
        self.guestAccountEnabled = accounts.guestAccountEnabled
        self.autoLoginUser = accounts.autoLoginUser
        self.rootAccountEnabled = accounts.rootAccountEnabled
        self.remoteAppleEventsEnabled = remoteAppleEventsEnabled
        self.remoteManagementEnabled = remoteManagementEnabled
        self.softwareUpdate = softwareUpdate
        self.xprotectVersion = malwareProtection.xprotectVersion
        self.xprotectRemediatorVersion = malwareProtection.xprotectRemediatorVersion
        self.mrtVersion = malwareProtection.mrtVersion
    }

    enum CodingKeys: String, CodingKey {
        case guestAccountEnabled = "guest_account_enabled"
        case autoLoginUser = "auto_login_user"
        case rootAccountEnabled = "root_account_enabled"
        case remoteAppleEventsEnabled = "remote_apple_events_enabled"
        case remoteManagementEnabled = "remote_management_enabled"
        case softwareUpdate = "software_update"
        case xprotectVersion = "xprotect_version"
        case xprotectRemediatorVersion = "xprotect_remediator_version"
        case mrtVersion = "mrt_version"
    }
}

/// Software Update automation settings from `com.apple.SoftwareUpdate` and `com.apple.commerce`.
public struct SoftwareUpdateSettings: Codable, Sendable {
    /// `AutomaticCheckEnabled` (absent means true, Apple's default).
    public let automaticCheck: Bool?

    /// `AutomaticDownload`.
    public let automaticDownload: Bool?

    /// `ConfigDataInstall` and `CriticalUpdateInstall` (nil when both are absent).
    public let installSecurityResponses: Bool?

    /// `AutomaticallyInstallMacOSUpdates`.
    public let installSystemUpdates: Bool?

    /// `AutoUpdate` from the commerce preferences.
    public let installAppUpdates: Bool?

    /// `LastFullSuccessfulDate` as ISO 8601 UTC.
    public let lastSuccessfulCheck: String?

    public init(
        automaticCheck: Bool? = nil,
        automaticDownload: Bool? = nil,
        installSecurityResponses: Bool? = nil,
        installSystemUpdates: Bool? = nil,
        installAppUpdates: Bool? = nil,
        lastSuccessfulCheck: String? = nil
    ) {
        self.automaticCheck = automaticCheck
        self.automaticDownload = automaticDownload
        self.installSecurityResponses = installSecurityResponses
        self.installSystemUpdates = installSystemUpdates
        self.installAppUpdates = installAppUpdates
        self.lastSuccessfulCheck = lastSuccessfulCheck
    }

    enum CodingKeys: String, CodingKey {
        case automaticCheck = "automatic_check"
        case automaticDownload = "automatic_download"
        case installSecurityResponses = "install_security_responses"
        case installSystemUpdates = "install_system_updates"
        case installAppUpdates = "install_app_updates"
        case lastSuccessfulCheck = "last_successful_check"
    }
}
