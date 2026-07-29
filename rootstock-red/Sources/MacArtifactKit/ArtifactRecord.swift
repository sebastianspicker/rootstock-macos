import Foundation

/// Record of a path touched during a run (for cleanup and audit).
public struct ArtifactRecord: Codable, Sendable, Equatable, Identifiable {
    public var id: String
    public var path: String
    public var action: String
    public var hash: String?
    public var cleanupRecipe: String?
    public var timestamp: Date

    public init(
        id: String = UUID().uuidString,
        path: String,
        action: String,
        hash: String? = nil,
        cleanupRecipe: String? = nil,
        timestamp: Date = Date()
    ) {
        self.id = id
        self.path = path
        self.action = action
        self.hash = hash
        self.cleanupRecipe = cleanupRecipe
        self.timestamp = timestamp
    }
}
