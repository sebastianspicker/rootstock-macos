import Foundation

/// Well-known macOS security artifact paths used across Rootstock products.
///
/// Products choose depth (live parse vs path presence vs offline tree-relative
/// resolution). This type only names locations.
public enum MacSecurityPaths: Sendable {
    // MARK: TCC

    /// Per-user TCC database (relative to home).
    public static let userTCCDatabaseRelative =
        "Library/Application Support/com.apple.TCC/TCC.db"

    public static let systemTCCDatabase =
        "/Library/Application Support/com.apple.TCC/TCC.db"

    public static func userTCCDatabase(home: URL) -> URL {
        home.appendingPathComponent(userTCCDatabaseRelative)
    }

    public static func userTCCDatabase(homePath: String) -> String {
        (homePath as NSString).appendingPathComponent(userTCCDatabaseRelative)
    }

    // MARK: Launchd / persistence

    public static let systemLaunchDaemons = "/Library/LaunchDaemons"
    public static let systemLaunchAgents = "/Library/LaunchAgents"
    public static let userLaunchAgentsRelative = "Library/LaunchAgents"
    public static let appleLaunchDaemons = "/System/Library/LaunchDaemons"
    public static let appleLaunchAgents = "/System/Library/LaunchAgents"

    public static func userLaunchAgents(home: URL) -> URL {
        home.appendingPathComponent(userLaunchAgentsRelative)
    }

    // MARK: BTM / login items

    public static let backgroundItemsBTMRelative =
        "Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm"

    public static let btmDataDirectory =
        "/Library/Application Support/com.apple.backgroundtaskmanagementagent"

    // MARK: Sudoers

    public static let sudoers = "/etc/sudoers"
    public static let sudoersD = "/etc/sudoers.d"

    // MARK: MDM / PPPC

    public static let configurationProfiles =
        "/Library/ConfigurationProfiles"
    public static let pppcPayloadType =
        "com.apple.TCC.configuration-profile-policy"

    // MARK: System extensions

    public static let systemExtensions =
        "/Library/SystemExtensions"

    // MARK: Authorization plugins

    public static let authorizationPlugins =
        "/Library/Security/SecurityAgentPlugins"

    // MARK: Kerberos (path vocabulary only)

    public static let krb5Conf = "/etc/krb5.conf"
    public static let krb5Keytabs = "/etc/krb5.keytab"
}
