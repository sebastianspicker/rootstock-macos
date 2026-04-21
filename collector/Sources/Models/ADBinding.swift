import Foundation

/// Active Directory binding status for this Mac.
///
/// Populated by parsing `dsconfigad -show` output.  When the Mac is not
/// AD-bound, `isBound` is false and all optional fields are nil.
public struct ADBinding: Codable, Sendable {
    public let isBound: Bool
    public let realm: String?
    public let forest: String?
    public let computerAccount: String?
    public let organizationalUnit: String?
    public let preferredDC: String?
    public let groupMappings: [ADGroupMapping]

    public init(
        isBound: Bool,
        realm: String? = nil,
        forest: String? = nil,
        computerAccount: String? = nil,
        organizationalUnit: String? = nil,
        preferredDC: String? = nil,
        groupMappings: [ADGroupMapping] = []
    ) {
        self.isBound = isBound
        self.realm = realm
        self.forest = forest
        self.computerAccount = computerAccount
        self.organizationalUnit = organizationalUnit
        self.preferredDC = preferredDC
        self.groupMappings = groupMappings
    }

    enum CodingKeys: String, CodingKey {
        case isBound = "is_bound"
        case realm
        case forest
        case computerAccount = "computer_account"
        case organizationalUnit = "organizational_unit"
        case preferredDC = "preferred_dc"
        case groupMappings = "group_mappings"
    }
}

/// Mapping from an AD group to a local macOS group (e.g., "Domain Admins" → "admin").
public struct ADGroupMapping: Codable, Sendable {
    public let adGroup: String
    public let localGroup: String

    public init(adGroup: String, localGroup: String) {
        self.adGroup = adGroup
        self.localGroup = localGroup
    }

    enum CodingKeys: String, CodingKey {
        case adGroup = "ad_group"
        case localGroup = "local_group"
    }
}
