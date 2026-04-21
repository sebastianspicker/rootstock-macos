import Foundation

/// A persistence mechanism: a launchd job, login item, cron job, or login hook.
public struct LaunchItem: GraphNode {
    public var nodeType: String { "LaunchItem" }

    /// Label or identifier for this persistence item (e.g., "com.apple.logd").
    public let label: String

    /// Path to the plist, crontab, or hook configuration file.
    public let path: String

    /// How this item achieves persistence.
    public let type: ItemType

    /// Binary or script that is executed.
    public let program: String?

    /// Whether the item starts automatically at boot or login.
    public let runAtLoad: Bool

    /// User account this item runs as (nil = inherits from context).
    public let user: String?

    /// Owner of the plist configuration file (e.g., "root").
    public let plistOwner: String?

    /// Owner of the program binary (e.g., "root").
    public let programOwner: String?

    /// Whether the plist file is writable by a non-root user.
    public let plistWritableByNonRoot: Bool

    /// Whether the program binary is writable by a non-root user.
    public let programWritableByNonRoot: Bool

    public enum ItemType: String, Codable, Sendable {
        case daemon
        case agent
        case loginItem = "login_item"
        case cron
        case loginHook = "login_hook"
    }

    public init(
        label: String,
        path: String,
        type: ItemType,
        program: String?,
        runAtLoad: Bool,
        user: String?,
        plistOwner: String? = nil,
        programOwner: String? = nil,
        plistWritableByNonRoot: Bool = false,
        programWritableByNonRoot: Bool = false
    ) {
        self.label = label
        self.path = path
        self.type = type
        self.program = program
        self.runAtLoad = runAtLoad
        self.user = user
        self.plistOwner = plistOwner
        self.programOwner = programOwner
        self.plistWritableByNonRoot = plistWritableByNonRoot
        self.programWritableByNonRoot = programWritableByNonRoot
    }

    enum CodingKeys: String, CodingKey {
        case label
        case path
        case type
        case program
        case runAtLoad = "run_at_load"
        case user
        case plistOwner = "plist_owner"
        case programOwner = "program_owner"
        case plistWritableByNonRoot = "plist_writable_by_non_root"
        case programWritableByNonRoot = "program_writable_by_non_root"
    }
}
