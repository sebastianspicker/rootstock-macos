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

    /// Encodes unknown (nil) tri-state fields as explicit nulls, as the
    /// collector-scan schema requires the keys to be present.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try Self.encodeTriState(enabled, forKey: .enabled, in: &container)
        try Self.encodeTriState(stealthMode, forKey: .stealthMode, in: &container)
        try Self.encodeTriState(allowSigned, forKey: .allowSigned, in: &container)
        try Self.encodeTriState(allowBuiltIn, forKey: .allowBuiltIn, in: &container)
        try container.encode(appRules, forKey: .appRules)
    }

    private static func encodeTriState(
        _ value: Bool?,
        forKey key: CodingKeys,
        in container: inout KeyedEncodingContainer<CodingKeys>
    ) throws {
        if let value {
            try container.encode(value, forKey: key)
        } else {
            try container.encodeNil(forKey: key)
        }
    }
}

/// A per-application firewall rule.
public struct FirewallAppRule: Codable, Sendable {
    public let bundleId: String
    public let allowIncoming: Bool?

    public init(bundleId: String, allowIncoming: Bool?) {
        self.bundleId = bundleId
        self.allowIncoming = allowIncoming
    }

    enum CodingKeys: String, CodingKey {
        case bundleId = "bundle_id"
        case allowIncoming = "allow_incoming"
    }

    /// Encodes an unknown (nil) `allow_incoming` as an explicit null, as the
    /// collector-scan schema requires the key to be present.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(bundleId, forKey: .bundleId)
        if let allowIncoming {
            try container.encode(allowIncoming, forKey: .allowIncoming)
        } else {
            try container.encodeNil(forKey: .allowIncoming)
        }
    }
}
