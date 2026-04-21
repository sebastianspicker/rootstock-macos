import Foundation

/// A sudoers configuration rule parsed from /etc/sudoers or /etc/sudoers.d/.
public struct SudoersRule: GraphNode {
    public var nodeType: String { "SudoersRule" }

    /// Username or group (prefixed with %) this rule applies to.
    public let user: String

    /// Host specification (usually "ALL").
    public let host: String

    /// Command specification.
    public let command: String

    /// Whether the NOPASSWD tag is set (no password required).
    public let nopasswd: Bool

    public init(user: String, host: String, command: String, nopasswd: Bool) {
        self.user = user
        self.host = host
        self.command = command
        self.nopasswd = nopasswd
    }

    enum CodingKeys: String, CodingKey {
        case user
        case host
        case command
        case nopasswd
    }
}
