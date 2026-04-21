import Foundation

/// A macOS Authorization Services right and its configuration.
public struct AuthorizationRight: GraphNode {
    public var nodeType: String { "AuthorizationRight" }

    /// The right name (e.g., "system.privilege.admin").
    public let name: String

    /// The rule governing this right (e.g., "authenticate-admin-nonshared").
    public let rule: String?

    /// Whether root is allowed to bypass authentication.
    public let allowRoot: Bool

    /// Whether the user must authenticate to exercise this right.
    public let requireAuthentication: Bool

    public init(
        name: String,
        rule: String?,
        allowRoot: Bool,
        requireAuthentication: Bool
    ) {
        self.name = name
        self.rule = rule
        self.allowRoot = allowRoot
        self.requireAuthentication = requireAuthentication
    }

    enum CodingKeys: String, CodingKey {
        case name
        case rule
        case allowRoot = "allow_root"
        case requireAuthentication = "require_authentication"
    }
}
