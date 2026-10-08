import Foundation

/// A certificate with explicit trust settings in the user or admin trust-settings domain.
public struct TrustedCertificate: GraphNode {
    public var nodeType: String { "TrustedCertificate" }

    /// Lower-case hex SHA-256 of the DER certificate.
    public let sha256: String

    /// Subject summary (`SecCertificateCopySubjectSummary`).
    public let subject: String

    /// Issuer common name when readable.
    public let issuer: String?

    /// Trust-settings domain the entry comes from.
    public let domain: Domain

    /// Strongest trust result across the entry's trust settings.
    public let trustResult: TrustResult

    /// Whether subject equals issuer.
    public let isSelfSigned: Bool

    /// ISO 8601 UTC expiry when readable.
    public let notAfter: String?

    public enum Domain: String, Codable, Sendable {
        case user
        case admin
    }

    public enum TrustResult: String, Codable, Sendable {
        case trustRoot = "trust_root"
        case trustAsRoot = "trust_as_root"
        case deny
        case unspecified
        case invalid
    }

    public init(
        sha256: String,
        subject: String,
        issuer: String? = nil,
        domain: Domain,
        trustResult: TrustResult,
        isSelfSigned: Bool,
        notAfter: String? = nil
    ) {
        self.sha256 = sha256
        self.subject = subject
        self.issuer = issuer
        self.domain = domain
        self.trustResult = trustResult
        self.isSelfSigned = isSelfSigned
        self.notAfter = notAfter
    }

    enum CodingKeys: String, CodingKey {
        case sha256
        case subject
        case issuer
        case domain
        case trustResult = "trust_result"
        case isSelfSigned = "is_self_signed"
        case notAfter = "not_after"
    }
}
