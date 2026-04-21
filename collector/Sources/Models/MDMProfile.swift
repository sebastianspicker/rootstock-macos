import Foundation

/// A TCC permission grant enforced via MDM configuration profile.
public struct TCCPolicy: Codable, Sendable {
    /// TCC service name as used in the profile (e.g. "SystemPolicyAllFiles", "Microphone").
    public let service: String

    /// Bundle identifier of the application granted or denied access.
    public let clientBundleId: String

    /// Whether this policy grants (true) or denies (false) access.
    public let allowed: Bool

    public init(service: String, clientBundleId: String, allowed: Bool) {
        self.service = service
        self.clientBundleId = clientBundleId
        self.allowed = allowed
    }

    enum CodingKeys: String, CodingKey {
        case service
        case clientBundleId = "client_bundle_id"
        case allowed
    }
}

/// An installed MDM configuration profile and the TCC policies it enforces.
public struct MDMProfile: GraphNode {
    public var nodeType: String { "MDMProfile" }

    /// Unique profile identifier (reverse-DNS, e.g. "com.example.mdm.profile").
    public let identifier: String

    /// Human-readable profile name.
    public let displayName: String

    /// Organization that issued the profile.
    public let organization: String?

    /// Profile installation date string.
    public let installDate: String?

    /// TCC permission policies declared in this profile's PayloadContent.
    /// Empty when the profile contains no Privacy Preferences Policy Control payload.
    public let tccPolicies: [TCCPolicy]

    public init(
        identifier: String,
        displayName: String,
        organization: String?,
        installDate: String?,
        tccPolicies: [TCCPolicy]
    ) {
        self.identifier = identifier
        self.displayName = displayName
        self.organization = organization
        self.installDate = installDate
        self.tccPolicies = tccPolicies
    }

    enum CodingKeys: String, CodingKey {
        case identifier
        case displayName = "display_name"
        case organization
        case installDate = "install_date"
        case tccPolicies = "tcc_policies"
    }
}
