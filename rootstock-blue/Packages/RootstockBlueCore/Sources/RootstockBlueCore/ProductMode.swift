import Foundation

/// Product mode is a profile, not a separate product fork.
/// Live IR, dead-box forensics, and research share one case model.
public enum ProductMode: String, Codable, Sendable, CaseIterable {
    /// Live Endpoint Security stream + triage collect.
    case liveIR = "live_ir"
    /// Offline image / logarchive / artifact tree parse only (no ES).
    case deadBox = "dead_box"
    /// Verbose ES session + fixture capture for detection engineering.
    case research = "research"

    public var bannerTitle: String {
        switch self {
        case .liveIR: return "LIVE IR"
        case .deadBox: return "OFFLINE FORENSICS"
        case .research: return "RESEARCH"
        }
    }

    /// AUTH/block is never the default in any mode.
    public var authBlockingDefault: Bool { false }
}
