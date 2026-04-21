import Foundation

/// A running process snapshot from `ps` output.
public struct RunningProcess: GraphNode {
    public var nodeType: String { "RunningProcess" }

    /// Process ID.
    public let pid: Int

    /// User running the process.
    public let user: String

    /// Command path or name.
    public let command: String

    /// Resolved bundle ID (nil if process doesn't correspond to a known .app).
    public let bundleId: String?

    public init(pid: Int, user: String, command: String, bundleId: String?) {
        self.pid = pid
        self.user = user
        self.command = command
        self.bundleId = bundleId
    }

    enum CodingKeys: String, CodingKey {
        case pid
        case user
        case command
        case bundleId = "bundle_id"
    }
}
