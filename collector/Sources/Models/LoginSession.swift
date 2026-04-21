import Foundation

/// An active login session discovered via the `who` command.
public struct LoginSession: GraphNode {
    public var nodeType: String { "LoginSession" }

    /// Username of the logged-in user.
    public let username: String

    /// Terminal or display (e.g., "ttys000", "console").
    public let terminal: String

    /// Login timestamp as reported by `who` (ISO 8601 or raw string).
    public let loginTime: String

    /// Type of session: console, ssh, screen_sharing, or tmux.
    public let sessionType: SessionType

    public enum SessionType: String, Codable, Sendable {
        case console
        case ssh
        case screenSharing = "screen_sharing"
        case tmux
    }

    public init(
        username: String,
        terminal: String,
        loginTime: String,
        sessionType: SessionType
    ) {
        self.username = username
        self.terminal = terminal
        self.loginTime = loginTime
        self.sessionType = sessionType
    }

    enum CodingKeys: String, CodingKey {
        case username
        case terminal
        case loginTime = "login_time"
        case sessionType = "session_type"
    }
}
