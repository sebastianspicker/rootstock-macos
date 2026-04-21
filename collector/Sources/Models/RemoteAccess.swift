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
}
