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

    public struct LaunchBehavior: Codable, Sendable {
        public let user: String?
        public let runAtLoad: Bool
        public let keepAlive: Bool

        public init(user: String?, runAtLoad: Bool, keepAlive: Bool) {
            self.user = user
            self.runAtLoad = runAtLoad
            self.keepAlive = keepAlive
        }
    }

    public struct Exposure: Codable, Sendable {
        public let machServices: [String]
        public let entitlements: [String]
        public let hasClientVerification: Bool

        public init(
            machServices: [String],
            entitlements: [String],
            hasClientVerification: Bool = false
        ) {
            self.machServices = machServices
            self.entitlements = entitlements
            self.hasClientVerification = hasClientVerification
        }
    }

    public init(
        label: String,
        path: String,
        program: String?,
        type: ServiceType,
        launch: LaunchBehavior,
        exposure: Exposure
    ) {
        self.label = label
        self.path = path
        self.program = program
        self.type = type
        self.user = launch.user
        self.runAtLoad = launch.runAtLoad
        self.keepAlive = launch.keepAlive
        self.machServices = exposure.machServices
        self.entitlements = exposure.entitlements
        self.hasClientVerification = exposure.hasClientVerification
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
