import Foundation

/// A listening TCP socket or bound UDP socket reported by `netstat`.
public struct NetworkListener: GraphNode {
    public var nodeType: String { "NetworkListener" }

    /// Transport protocol of the socket.
    public let networkProtocol: TransportProtocol

    /// Local address as printed by netstat (`*`, `127.0.0.1`, `::1`, `192.168.1.5`).
    public let address: String

    /// Local port.
    public let port: Int

    /// Whether the socket is bound to a loopback address only (`*` and wildcard addresses are not).
    public let isLoopback: Bool

    /// `listen` for TCP LISTEN sockets, `bound` for UDP sockets.
    public let state: State

    /// Owning process ID from the netstat `pid` column.
    public let pid: Int?

    /// Command of the owning process (full path when available).
    public let processName: String?

    /// User owning the process.
    public let user: String?

    /// Bundle ID of the application the owning process belongs to.
    public let bundleId: String?

    public enum TransportProtocol: String, Codable, Sendable {
        case tcp
        case udp
    }

    public enum State: String, Codable, Sendable {
        case listen
        case bound
    }

    /// The process that owns the socket, when it could be resolved.
    public struct Owner: Codable, Sendable {
        public let pid: Int?
        public let processName: String?
        public let user: String?
        public let bundleId: String?

        public init(
            pid: Int? = nil,
            processName: String? = nil,
            user: String? = nil,
            bundleId: String? = nil
        ) {
            self.pid = pid
            self.processName = processName
            self.user = user
            self.bundleId = bundleId
        }
    }

    public init(
        networkProtocol: TransportProtocol,
        address: String,
        port: Int,
        isLoopback: Bool,
        state: State,
        owner: Owner = Owner()
    ) {
        self.networkProtocol = networkProtocol
        self.address = address
        self.port = port
        self.isLoopback = isLoopback
        self.state = state
        self.pid = owner.pid
        self.processName = owner.processName
        self.user = owner.user
        self.bundleId = owner.bundleId
    }

    enum CodingKeys: String, CodingKey {
        case networkProtocol = "protocol"
        case address
        case port
        case isLoopback = "is_loopback"
        case state
        case pid
        case processName = "process_name"
        case user
        case bundleId = "bundle_id"
    }
}
