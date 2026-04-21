import Foundation

/// A data source that collects security-relevant metadata from the local system.
public protocol DataSource {
    /// Human-readable name for logging (e.g., "TCC Database")
    var name: String { get }

    /// Whether this source requires elevated privileges to collect fully
    var requiresElevation: Bool { get }

    /// Collect data from this source.
    /// Returns partial results on failure — never throws to abort the entire scan.
    func collect() async -> DataSourceResult
}

/// The result of a single data source collection pass.
public struct DataSourceResult {
    public let nodes: [any GraphNode]
    public let errors: [CollectionError]

    public init(nodes: [any GraphNode], errors: [CollectionError]) {
        self.nodes = nodes
        self.errors = errors
    }
}

/// A non-fatal error encountered during data collection.
public struct CollectionError: Codable, Sendable {
    public let source: String
    public let message: String
    public let recoverable: Bool

    public init(source: String, message: String, recoverable: Bool) {
        self.source = source
        self.message = message
        self.recoverable = recoverable
    }
}
