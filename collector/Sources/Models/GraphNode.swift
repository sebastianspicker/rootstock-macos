import Foundation

/// Marker protocol for all graph node types produced by data sources.
/// All conforming types must be Codable for JSON serialization.
public protocol GraphNode: Codable, Sendable {
    var nodeType: String { get }
}
