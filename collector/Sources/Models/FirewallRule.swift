import Foundation

/// macOS Application Firewall (ALF) global status and per-app rules.
public struct FirewallStatus: Codable, Sendable, GraphNode {
    public let enabled: Bool?
    public let stealthMode: Bool?
    public let allowSigned: Bool?
    public let allowBuiltIn: Bool?
    public let appRules: [FirewallAppRule]

    public var nodeType: String { "FirewallPolicy" }

    public init(
        enabled: Bool?,
        stealthMode: Bool?,
        allowSigned: Bool?,
        allowBuiltIn: Bool?,
        appRules: [FirewallAppRule]
    ) {
        self.enabled = enabled
        self.stealthMode = stealthMode
        self.allowSigned = allowSigned
        self.allowBuiltIn = allowBuiltIn
        self.appRules = appRules
    }

    enum CodingKeys: String, CodingKey {
        case enabled
        case stealthMode = "stealth_mode"
        case allowSigned = "allow_signed"
        case allowBuiltIn = "allow_built_in"
        case appRules = "app_rules"
    }
}

/// A per-application firewall rule.
public struct FirewallAppRule: Codable, Sendable {
    public let bundleId: String
    public let allowIncoming: Bool

    public init(bundleId: String, allowIncoming: Bool) {
        self.bundleId = bundleId
        self.allowIncoming = allowIncoming
    }

    enum CodingKeys: String, CodingKey {
        case bundleId = "bundle_id"
        case allowIncoming = "allow_incoming"
    }
}
