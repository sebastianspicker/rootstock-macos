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

    public struct Rules: Codable, Sendable {
        public let fileReadRules: [String]
        public let fileWriteRules: [String]
        public let machLookupRules: [String]
        public let networkRules: [String]
        public let iokitRules: [String]

        public init(
            fileReadRules: [String] = [],
            fileWriteRules: [String] = [],
            machLookupRules: [String] = [],
            networkRules: [String] = [],
            iokitRules: [String] = []
        ) {
            self.fileReadRules = fileReadRules
            self.fileWriteRules = fileWriteRules
            self.machLookupRules = machLookupRules
            self.networkRules = networkRules
            self.iokitRules = iokitRules
        }
    }

    public struct Exposure: Codable, Sendable {
        public let exceptionCount: Int
        public let hasUnconstrainedNetwork: Bool
        public let hasUnconstrainedFileRead: Bool

        public init(
            exceptionCount: Int = 0,
            hasUnconstrainedNetwork: Bool = false,
            hasUnconstrainedFileRead: Bool = false
        ) {
            self.exceptionCount = exceptionCount
            self.hasUnconstrainedNetwork = hasUnconstrainedNetwork
            self.hasUnconstrainedFileRead = hasUnconstrainedFileRead
        }
    }

    public init(
        bundleId: String,
        profileSource: String = "none",
        rules: Rules = Rules(),
        exposure: Exposure = Exposure()
    ) {
        self.bundleId = bundleId
        self.profileSource = profileSource
        self.fileReadRules = rules.fileReadRules
        self.fileWriteRules = rules.fileWriteRules
        self.machLookupRules = rules.machLookupRules
        self.networkRules = rules.networkRules
        self.iokitRules = rules.iokitRules
        self.exceptionCount = exposure.exceptionCount
        self.hasUnconstrainedNetwork = exposure.hasUnconstrainedNetwork
        self.hasUnconstrainedFileRead = exposure.hasUnconstrainedFileRead
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
