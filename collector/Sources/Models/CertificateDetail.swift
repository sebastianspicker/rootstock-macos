import Foundation

/// A single certificate in a code signing certificate chain.
public struct CertificateDetail: Codable, Sendable {
    public let commonName: String?
    public let organization: String?
    public let sha256: String
    public let validFrom: String?
    public let validTo: String?
    public let isRoot: Bool

    public init(
        commonName: String?,
        organization: String?,
        sha256: String,
        validFrom: String?,
        validTo: String?,
        isRoot: Bool
    ) {
        self.commonName = commonName
        self.organization = organization
        self.sha256 = sha256
        self.validFrom = validFrom
        self.validTo = validTo
        self.isRoot = isRoot
    }

    enum CodingKeys: String, CodingKey {
        case commonName = "common_name"
        case organization
        case sha256
        case validFrom = "valid_from"
        case validTo = "valid_to"
        case isRoot = "is_root"
    }
}
