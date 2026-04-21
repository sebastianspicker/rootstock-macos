import Foundation

/// A launchd-managed XPC service discovered via LaunchDaemon/LaunchAgent plist.
public struct XPCService: GraphNode {
    public var nodeType: String { "XPCService" }

    /// The launchd label (e.g., "com.apple.logd").
    public let label: String

    /// Path to the LaunchDaemon/LaunchAgent plist file.
    public let path: String

    /// Resolved binary path from Program or ProgramArguments[0].
    public let program: String?

    /// Whether this is a system-wide daemon or per-user agent.
    public let type: ServiceType

    /// UserName field from plist (nil = current user for agents).
    public let user: String?

    /// Whether launchd starts the service automatically at load.
    public let runAtLoad: Bool

    /// Whether launchd restarts the service after it exits.
    public let keepAlive: Bool

    /// Mach service names this service registers (keys from MachServices dict).
    public let machServices: [String]

    /// Entitlement keys present in the service binary (empty if binary is inaccessible).
    public let entitlements: [String]

    /// Whether the service plist declares SMAuthorizedClients (client verification).
    public let hasClientVerification: Bool

    public enum ServiceType: String, Codable, Sendable {
        case daemon
        case agent
    }

    public init(
        label: String,
        path: String,
        program: String?,
        type: ServiceType,
        user: String?,
        runAtLoad: Bool,
        keepAlive: Bool,
        machServices: [String],
        entitlements: [String],
        hasClientVerification: Bool = false
    ) {
        self.label = label
        self.path = path
        self.program = program
        self.type = type
        self.user = user
        self.runAtLoad = runAtLoad
        self.keepAlive = keepAlive
        self.machServices = machServices
        self.entitlements = entitlements
        self.hasClientVerification = hasClientVerification
    }

    enum CodingKeys: String, CodingKey {
        case label
        case path
        case program
        case type
        case user
        case runAtLoad = "run_at_load"
        case keepAlive = "keep_alive"
        case machServices = "mach_services"
        case entitlements
        case hasClientVerification = "has_client_verification"
    }
}
