import Foundation

/// Well-known remote access service identifiers.
public enum RemoteServiceName {
    public static let ssh = "ssh"
    public static let screenSharing = "screen_sharing"
}

/// A remote access service (SSH, Screen Sharing) and its configuration.
public struct RemoteAccessService: Codable, Sendable, GraphNode {
    public let service: String
    public let enabled: Bool?
    public let port: Int?
    public let config: [String: String]

    public var nodeType: String { "RemoteAccessService" }

    public init(service: String, enabled: Bool?, port: Int?, config: [String: String]) {
        self.service = service
        self.enabled = enabled
        self.port = port
        self.config = config
    }

    enum CodingKeys: String, CodingKey {
        case service
        case enabled
        case port
        case config
    }

    /// Encodes an unknown (nil) `enabled` as an explicit null, as the
    /// collector-scan schema requires the key to be present.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(service, forKey: .service)
        if let enabled {
            try container.encode(enabled, forKey: .enabled)
        } else {
            try container.encodeNil(forKey: .enabled)
        }
        try container.encodeIfPresent(port, forKey: .port)
        try container.encode(config, forKey: .config)
    }
}
