import Foundation

/// A SecurityAgent authorization plugin bundle discovered in /Library/Security/SecurityAgentPlugins/.
public struct AuthorizationPlugin: GraphNode {
    public var nodeType: String { "AuthorizationPlugin" }

    /// Plugin bundle name (e.g., "MyAuthPlugin").
    public let name: String

    /// Full path to the .bundle directory.
    public let path: String

    /// Code signing team ID (nil if unsigned).
    public let teamId: String?

    public init(name: String, path: String, teamId: String?) {
        self.name = name
        self.path = path
        self.teamId = teamId
    }

    enum CodingKeys: String, CodingKey {
        case name
        case path
        case teamId = "team_id"
    }
}
