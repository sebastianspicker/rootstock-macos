/// Cost / depth profile for assess runs.
public enum ScanProfile: String, Codable, Sendable, CaseIterable {
    case quick
    case standard
    case deep
    case paranoid

    /// Relative cost tag for filtering expensive collectors/checks.
    public var maxCost: CollectorCost {
        switch self {
        case .quick: return .low
        case .standard: return .medium
        case .deep: return .high
        case .paranoid: return .expensive
        }
    }
}

/// Approximate collection cost (used for profile filtering).
public enum CollectorCost: Int, Codable, Sendable, Comparable {
    case low = 1
    case medium = 2
    case high = 3
    case expensive = 4

    public static func < (lhs: CollectorCost, rhs: CollectorCost) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}
