import CryptoKit
import Foundation
import Models
import Security

/// Enumerates certificates with explicit trust settings in the user and admin domains.
///
/// The system domain (Apple's built-in roots) is not collected. Only public
/// certificate metadata is read: DER bytes are hashed and never stored.
public struct TrustSettingsDataSource: DataSource {
    public let name = "Trust Settings"
    public let requiresElevation = false

    public init() {}

    public func collect() async -> DataSourceResult {
        var certificates: [TrustedCertificate] = []
        var errors: [CollectionError] = []
        let domains: [(SecTrustSettingsDomain, TrustedCertificate.Domain)] = [(.user, .user), (.admin, .admin)]
        for (secDomain, domain) in domains {
            switch Self.copyCertificates(secDomain) {
            case .success(let entries):
                certificates.append(contentsOf: entries.map { Self.describe($0, secDomain: secDomain, domain: domain) })
            case .failure(let failure):
                let status = failure.status
                errors.append(CollectionError(
                    source: name,
                    message: "SecTrustSettingsCopyCertificates failed for the \(domain.rawValue) domain "
                        + "(OSStatus \(status): \(Self.statusMessage(status)))",
                    recoverable: true
                ))
            }
        }
        certificates.sort { ($0.domain.rawValue, $0.sha256) < ($1.domain.rawValue, $1.sha256) }
        return DataSourceResult(nodes: certificates, errors: errors)
    }

    struct StatusError: Error {
        let status: OSStatus
    }

    /// `errSecNoTrustSettings` means the domain has no entries, which is not an error.
    private static func copyCertificates(_ domain: SecTrustSettingsDomain) -> Result<[SecCertificate], StatusError> {
        var array: CFArray?
        let status = SecTrustSettingsCopyCertificates(domain, &array)
        if status == errSecNoTrustSettings {
            return .success([])
        }
        guard status == errSecSuccess else {
            return .failure(StatusError(status: status))
        }
        return .success((array as? [SecCertificate]) ?? [])
    }

    private static func describe(
        _ certificate: SecCertificate,
        secDomain: SecTrustSettingsDomain,
        domain: TrustedCertificate.Domain
    ) -> TrustedCertificate {
        let der = SecCertificateCopyData(certificate) as Data
        let subject = (SecCertificateCopySubjectSummary(certificate) as String?) ?? ""
        let values = copyValues(certificate)
        let selfSigned = isSelfSigned(certificate)
        let issuer = values.flatMap { issuerName(from: $0) } ?? (selfSigned && !subject.isEmpty ? subject : nil)
        return TrustedCertificate(
            sha256: sha256Hex(der),
            subject: subject,
            issuer: issuer,
            domain: domain,
            trustResult: trustResult(for: certificate, domain: secDomain),
            isSelfSigned: selfSigned,
            notAfter: values.flatMap { notAfter(from: $0) }
        )
    }

    static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private static func isSelfSigned(_ certificate: SecCertificate) -> Bool {
        guard let subject = SecCertificateCopyNormalizedSubjectSequence(certificate) as Data?,
              let issuer = SecCertificateCopyNormalizedIssuerSequence(certificate) as Data? else {
            return false
        }
        return subject == issuer
    }

    private static func copyValues(_ certificate: SecCertificate) -> [String: Any]? {
        let keys = [kSecOIDX509V1IssuerName, kSecOIDX509V1ValidityNotAfter] as CFArray
        return SecCertificateCopyValues(certificate, keys, nil) as? [String: Any]
    }

    /// Issuer common name, falling back to the first textual issuer component.
    static func issuerName(from values: [String: Any]) -> String? {
        guard let issuer = values[kSecOIDX509V1IssuerName as String] as? [String: Any],
              let components = issuer[kSecPropertyKeyValue as String] as? [[String: Any]] else {
            return nil
        }
        let pairs = components.compactMap { component -> (String, String)? in
            guard let label = component[kSecPropertyKeyLabel as String] as? String,
                  let value = component[kSecPropertyKeyValue as String] as? String else { return nil }
            return (label, value)
        }
        let commonName = kSecOIDCommonName as String
        return pairs.first { $0.0 == commonName }?.1 ?? pairs.first?.1
    }

    static func notAfter(from values: [String: Any]) -> String? {
        guard let entry = values[kSecOIDX509V1ValidityNotAfter as String] as? [String: Any] else {
            return nil
        }
        let raw = entry[kSecPropertyKeyValue as String]
        let date: Date?
        if let number = raw as? NSNumber {
            date = Date(timeIntervalSinceReferenceDate: number.doubleValue)
        } else {
            date = raw as? Date
        }
        return date.map(iso8601)
    }

    private static func trustResult(
        for certificate: SecCertificate,
        domain: SecTrustSettingsDomain
    ) -> TrustedCertificate.TrustResult {
        var settings: CFArray?
        guard SecTrustSettingsCopyTrustSettings(certificate, domain, &settings) == errSecSuccess else {
            return .invalid
        }
        let entries = (settings as? [[String: Any]]) ?? []
        return strongestResult(entries.map { $0[kSecTrustSettingsResult as String] as? NSNumber }.map { $0?.int32Value })
    }

    /// Strongest result across trust-settings entries; an empty array means `trust_root`,
    /// and an entry without `kSecTrustSettingsResult` defaults to `trust_root` (Apple docs).
    static func strongestResult(_ rawResults: [Int32?]) -> TrustedCertificate.TrustResult {
        guard !rawResults.isEmpty else { return .trustRoot }
        let ranked: [TrustedCertificate.TrustResult] = [.trustRoot, .trustAsRoot, .deny, .unspecified, .invalid]
        let results = Set(rawResults.map { mapResult($0) })
        return ranked.first { results.contains($0) } ?? .invalid
    }

    static func mapResult(_ raw: Int32?) -> TrustedCertificate.TrustResult {
        guard let raw else { return .trustRoot }
        switch SecTrustSettingsResult(rawValue: UInt32(bitPattern: raw)) {
        case .trustRoot: return .trustRoot
        case .trustAsRoot: return .trustAsRoot
        case .deny: return .deny
        case .unspecified: return .unspecified
        default: return .invalid
        }
    }

    private static func statusMessage(_ status: OSStatus) -> String {
        (SecCopyErrorMessageString(status, nil) as String?) ?? "unknown error"
    }

    static func iso8601(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.string(from: date)
    }
}
