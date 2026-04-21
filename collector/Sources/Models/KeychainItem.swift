import Foundation

/// Keychain item metadata. NO secret values (passwords, keys, tokens) are ever stored here.
public struct KeychainItem: GraphNode {
    public var nodeType: String { "KeychainItem" }

    /// Human-readable label from the item's metadata.
    public let label: String

    /// Class of keychain item.
    public let kind: Kind

    /// Service name (generic password) or server hostname (internet password).
    public let service: String?

    /// Keychain access group, e.g. "TEAMID.com.example.app" or a shared group.
    public let accessGroup: String?

    /// Bundle IDs (or executable paths where no bundle exists) of applications
    /// explicitly listed in this item's ACL as trusted to read it without prompting.
    public let trustedApps: [String]

    public enum Kind: String, Codable, Sendable {
        case genericPassword  = "generic_password"
        case internetPassword = "internet_password"
        case certificate
        case key
    }

    public init(
        label: String,
        kind: Kind,
        service: String?,
        accessGroup: String?,
        trustedApps: [String]
    ) {
        self.label = label
        self.kind = kind
        self.service = service
        self.accessGroup = accessGroup
        self.trustedApps = trustedApps
    }

    enum CodingKeys: String, CodingKey {
        case label
        case kind
        case service
        case accessGroup = "access_group"
        case trustedApps = "trusted_apps"
    }
}
