import Foundation

/// macOS version detected at runtime, named by marketing name.
///
/// Apple switched from sequential versioning (14, 15…) to year-based versioning
/// starting with macOS 26 (2025, formerly planned as "macOS 16 Tahoe").
/// `ProcessInfo.operatingSystemVersion.majorVersion` returns 26 for Tahoe.
public enum MacOSVersion: Comparable, Sendable {
    case sonoma    // macOS 14.x
    case sequoia   // macOS 15.x
    case tahoe     // macOS 26.x  (year-based: 2025 release, marketed as "Tahoe")
    case unknown(major: Int, minor: Int)

    /// Detect the running macOS version from `ProcessInfo`.
    public static func detect() -> MacOSVersion {
        let v = ProcessInfo.processInfo.operatingSystemVersion
        return from(majorVersion: v.majorVersion, minorVersion: v.minorVersion)
    }

    /// Construct from explicit version numbers (useful for testing).
    public static func from(majorVersion: Int, minorVersion: Int = 0) -> MacOSVersion {
        switch majorVersion {
        case 14: return .sonoma
        case 15: return .sequoia
        case 26: return .tahoe
        default: return .unknown(major: majorVersion, minor: minorVersion)
        }
    }

    /// Human-readable marketing name.
    public var displayString: String {
        switch self {
        case .sonoma:                          return "macOS 14 Sonoma"
        case .sequoia:                         return "macOS 15 Sequoia"
        case .tahoe:                           return "macOS 26 Tahoe"
        case .unknown(let major, let minor):   return "macOS \(major).\(minor) (unknown)"
        }
    }

    // MARK: - Comparable

    // Raw ordering for comparison (unknown versions sort last)
    private var sortKey: Int {
        switch self {
        case .sonoma:           return 14
        case .sequoia:          return 15
        case .tahoe:            return 26
        case .unknown(let m, _): return m
        }
    }

    public static func < (lhs: MacOSVersion, rhs: MacOSVersion) -> Bool {
        lhs.sortKey < rhs.sortKey
    }
}
