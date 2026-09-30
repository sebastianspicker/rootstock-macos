import Foundation

/// Catalog entry for a living-off-the-land binary.
public struct LOOBin: Codable, Sendable, Equatable {
    public var name: String
    public var path: String
    public var tactics: [String]
    public var description: String

    public init(name: String, path: String, tactics: [String] = [], description: String = "") {
        self.name = name
        self.path = path
        self.tactics = tactics
        self.description = description
    }
}
