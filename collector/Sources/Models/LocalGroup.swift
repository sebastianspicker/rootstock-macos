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

    public static func members(inDirectoryServiceOutput output: String) -> [String] {
        let prefixes = [
            "GroupMembership:",
            "dsAttrTypeStandard:GroupMembership:",
        ]
        for line in output.components(separatedBy: .newlines) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard let prefix = prefixes.first(where: { trimmed.hasPrefix($0) }) else {
                continue
            }
            return trimmed.dropFirst(prefix.count)
                .split(whereSeparator: \.isWhitespace)
                .map(String.init)
        }
        return []
    }
}
