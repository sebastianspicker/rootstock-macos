import Foundation

/// Deep sandbox profile data extracted from an application's entitlements and
/// system sandbox profiles. Captures the actual rule categories that control
/// file, network, mach-port, and IOKit access within the sandbox container.
public struct SandboxProfile: Codable, Sendable, GraphNode {
    public let bundleId: String
    public let profileSource: String        // "entitlements", "system", "none"
    public let fileReadRules: [String]
    public let fileWriteRules: [String]
    public let machLookupRules: [String]    // mach services allowed
    public let networkRules: [String]
    public let iokitRules: [String]
    public let exceptionCount: Int
    public let hasUnconstrainedNetwork: Bool
    public let hasUnconstrainedFileRead: Bool

    public var nodeType: String { "SandboxProfile" }

    public init(
        bundleId: String,
        profileSource: String = "none",
        fileReadRules: [String] = [],
        fileWriteRules: [String] = [],
        machLookupRules: [String] = [],
        networkRules: [String] = [],
        iokitRules: [String] = [],
        exceptionCount: Int = 0,
        hasUnconstrainedNetwork: Bool = false,
        hasUnconstrainedFileRead: Bool = false
    ) {
        self.bundleId = bundleId
        self.profileSource = profileSource
        self.fileReadRules = fileReadRules
        self.fileWriteRules = fileWriteRules
        self.machLookupRules = machLookupRules
        self.networkRules = networkRules
        self.iokitRules = iokitRules
        self.exceptionCount = exceptionCount
        self.hasUnconstrainedNetwork = hasUnconstrainedNetwork
        self.hasUnconstrainedFileRead = hasUnconstrainedFileRead
    }

    enum CodingKeys: String, CodingKey {
        case bundleId = "bundle_id"
        case profileSource = "profile_source"
        case fileReadRules = "file_read_rules"
        case fileWriteRules = "file_write_rules"
        case machLookupRules = "mach_lookup_rules"
        case networkRules = "network_rules"
        case iokitRules = "iokit_rules"
        case exceptionCount = "exception_count"
        case hasUnconstrainedNetwork = "has_unconstrained_network"
        case hasUnconstrainedFileRead = "has_unconstrained_file_read"
    }
}
