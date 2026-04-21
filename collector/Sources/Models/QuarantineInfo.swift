import Foundation

/// Quarantine attribute metadata for a macOS application bundle.
///
/// macOS attaches a `com.apple.quarantine` extended attribute to files downloaded
/// from the internet. The attribute encodes the downloading agent, timestamp, and
/// flags indicating user approval and translocation state. This metadata is the
/// first-line defense in the Gatekeeper download protection chain.
///
/// Missing quarantine attributes on non-system applications indicate a potential
/// Gatekeeper bypass (ref: CVE-2022-42821, CVE-2024-44175).
public struct QuarantineInfo: Codable, Sendable {
    /// Whether the `com.apple.quarantine` extended attribute is present.
    public let hasQuarantineFlag: Bool

    /// Bundle ID of the application that downloaded this app (e.g., "com.apple.Safari").
    public let quarantineAgent: String?

    /// ISO 8601 timestamp derived from the quarantine attribute's hex epoch.
    public let quarantineTimestamp: String?

    /// Whether the user explicitly approved the quarantined app (flag 0x0040).
    public let wasUserApproved: Bool

    /// Whether the app was translocated to a randomised read-only path (flag 0x0020).
    public let wasTranslocated: Bool

    public init(
        hasQuarantineFlag: Bool,
        quarantineAgent: String? = nil,
        quarantineTimestamp: String? = nil,
        wasUserApproved: Bool = false,
        wasTranslocated: Bool = false
    ) {
        self.hasQuarantineFlag = hasQuarantineFlag
        self.quarantineAgent = quarantineAgent
        self.quarantineTimestamp = quarantineTimestamp
        self.wasUserApproved = wasUserApproved
        self.wasTranslocated = wasTranslocated
    }

    enum CodingKeys: String, CodingKey {
        case hasQuarantineFlag = "has_quarantine_flag"
        case quarantineAgent = "quarantine_agent"
        case quarantineTimestamp = "quarantine_timestamp"
        case wasUserApproved = "was_user_approved"
        case wasTranslocated = "was_translocated"
    }
}
