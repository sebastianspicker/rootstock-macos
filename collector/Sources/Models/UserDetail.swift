import Foundation

/// Extended user profile data collected via dscl.
///
/// Enriches the graph User node with shell, home directory, and hidden status.
/// Collected alongside local groups since both use dscl enumeration.
public struct UserDetail: Codable, Sendable, GraphNode {
    public var nodeType: String { "UserDetail" }

    /// Username (matches User node name).
    public let name: String

    /// User's login shell (e.g., "/bin/zsh").
    public let shell: String?

    /// User's home directory path.
    public let homeDir: String?

    /// Whether this is a hidden (service) account.
    public let isHidden: Bool

    /// Whether this user account originates from Active Directory.
    public let isADUser: Bool

    public init(name: String, shell: String?, homeDir: String?, isHidden: Bool, isADUser: Bool = false) {
        self.name = name
        self.shell = shell
        self.homeDir = homeDir
        self.isHidden = isHidden
        self.isADUser = isADUser
    }

    enum CodingKeys: String, CodingKey {
        case name
        case shell
        case homeDir = "home_dir"
        case isHidden = "is_hidden"
        case isADUser = "is_ad_user"
    }
}
