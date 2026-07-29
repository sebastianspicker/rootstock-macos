import Foundation

public extension Optional where Wrapped == Bool {
    /// Stable string for optional bool posture fields: `true` / `false` / `unknown`.
    var rootstockDescribe: String {
        switch self {
        case .some(true): return "true"
        case .some(false): return "false"
        case .none: return "unknown"
        }
    }
}
