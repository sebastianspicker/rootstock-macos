import Foundation

/// Allowlisted privileged operations only.
/// Explicitly absent: runShell, disableSIP, arbitrary path read, TCC bypass.
public enum XPCCapability: String, Codable, Sendable, CaseIterable {
    case getAgentStatus
    case startESProfile
    case stopES
    case collectPack
    case exportCase
    case getLossCounters

    public static let forbidden: [String] = [
        "runShell",
        "disableSIP",
        "readArbitraryPath",
        "bypassTCC",
        "crackFileVault",
        "installKext",
    ]

    public static func isAllowlisted(_ name: String) -> Bool {
        XPCCapability(rawValue: name) != nil
    }
}
