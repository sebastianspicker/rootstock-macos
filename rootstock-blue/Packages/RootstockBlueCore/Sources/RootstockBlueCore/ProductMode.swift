import Foundation

/// Product mode is a profile, not a separate product fork.
/// Offline forensics and synthetic research share one case model.
public enum ProductMode: String, Codable, Sendable, CaseIterable {
    /// Offline image / logarchive / artifact tree parse only (no ES).
    case deadBox = "dead_box"
    /// Synthetic fixture capture for detection engineering.
    case research = "research"

    public var bannerTitle: String {
        switch self {
        case .deadBox: return "OFFLINE FORENSICS"
        case .research: return "RESEARCH"
        }
    }

    /// AUTH/block is never the default in any mode.
    public var authBlockingDefault: Bool { false }
}
