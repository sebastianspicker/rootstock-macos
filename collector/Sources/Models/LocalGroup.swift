import Foundation

/// A local macOS group relevant to security analysis.
public struct LocalGroup: Codable, Sendable, GraphNode {
    public let name: String
    public let gid: Int
    public let members: [String]

    public var nodeType: String { "LocalGroup" }

    public init(name: String, gid: Int, members: [String]) {
        self.name = name
        self.gid = gid
        self.members = members
    }
}
