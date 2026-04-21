import Foundation

/// A TCC permission grant from the macOS privacy database.
public struct TCCGrant: Codable, Sendable, GraphNode {
    public let service: String
    public let displayName: String
    public let client: String
    public let clientType: Int
    public let authValue: Int
    public let authReason: Int
    public let scope: String
    public let lastModified: Int

    public var nodeType: String { "TCCGrant" }

    public init(
        service: String,
        displayName: String,
        client: String,
        clientType: Int,
        authValue: Int,
        authReason: Int,
        scope: String,
        lastModified: Int
    ) {
        self.service = service
        self.displayName = displayName
        self.client = client
        self.clientType = clientType
        self.authValue = authValue
        self.authReason = authReason
        self.scope = scope
        self.lastModified = lastModified
    }

    enum CodingKeys: String, CodingKey {
        case service
        case displayName = "display_name"
        case client
        case clientType = "client_type"
        case authValue = "auth_value"
        case authReason = "auth_reason"
        case scope
        case lastModified = "last_modified"
    }
}
