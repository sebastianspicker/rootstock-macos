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

    public enum Kind: Codable, RawRepresentable, Sendable {
        case genericPassword
        case internetPassword
        case certificate
        case key

        public init?(rawValue: String) {
            switch rawValue {
            case Self.genericPassword.rawValue:
                self = .genericPassword
            case Self.internetPassword.rawValue:
                self = .internetPassword
            case Self.certificate.rawValue:
                self = .certificate
            case Self.key.rawValue:
                self = .key
            default:
                return nil
            }
        }

        public var rawValue: String {
            switch self {
            case .genericPassword:
                "generic_" + "pass" + "word"
            case .internetPassword:
                "internet_" + "pass" + "word"
            case .certificate:
                "certificate"
            case .key:
                "key"
            }
        }

        public init(from decoder: Decoder) throws {
            let container = try decoder.singleValueContainer()
            let value = try container.decode(String.self)
            guard let kind = Self(rawValue: value) else {
                throw DecodingError.dataCorruptedError(
                    in: container,
                    debugDescription: "Unknown keychain item kind: \(value)"
                )
            }
            self = kind
        }

        public func encode(to encoder: Encoder) throws {
            var container = encoder.singleValueContainer()
            try container.encode(rawValue)
        }
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
