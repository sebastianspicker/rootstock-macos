import Foundation

/// A normalized entitlement key and its heuristic security classification.
///
/// This node records the entitlement name, not its value or effective runtime
/// permission. Category and criticality come from `EntitlementClassifier`, while
/// `isPrivate` reflects name-prefix detection.
public struct EntitlementInfo: Codable, Sendable, GraphNode {
    public let name: String
    public let isPrivate: Bool
    public let category: String
    public let isSecurityCritical: Bool

    public var nodeType: String { "Entitlement" }

    public init(name: String, isPrivate: Bool, category: String, isSecurityCritical: Bool) {
        self.name = name
        self.isPrivate = isPrivate
        self.category = category
        self.isSecurityCritical = isSecurityCritical
    }

    enum CodingKeys: String, CodingKey {
        case name
        case isPrivate = "is_private"
        case category
        case isSecurityCritical = "is_security_critical"
    }
}
