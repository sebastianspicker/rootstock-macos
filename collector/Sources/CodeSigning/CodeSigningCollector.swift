import Foundation
import Security
import CryptoKit
import Models

/// Information extracted from an app's code signature.
struct CodeSigningInfo {
    let signed: Bool
    let teamId: String?
    let signingIdentifier: String?
    let hardenedRuntime: Bool
    /// True if CS_REQUIRE_LV flag is set in the code signature.
    let libraryValidationFlag: Bool
    /// True if Security.framework analysis failed (app may still be unsigned).
    let analysisError: Bool
    /// True if CS_ADHOC flag is set — signed without a real certificate.
    let isAdhoc: Bool
    /// Full certificate chain from leaf to root.
    let certificateChain: [CertificateDetail]
}

/// Extracts code signing metadata from .app bundles using Security.framework.
struct CodeSigningAnalyzer {
    /// SIP-protected path prefixes (System Integrity Protection).
    private static let sipPrefixes = ["/System/", "/usr/bin/", "/usr/sbin/"]
    /// Paths under these prefixes are NOT SIP-protected despite matching a sipPrefix.
    private static let sipExceptions = ["/usr/local/"]

    /// Returns true if the app resides in a SIP-protected location.
    func isSIPProtected(appPath: String) -> Bool {
        for exception in Self.sipExceptions where appPath.hasPrefix(exception) {
            return false
        }
        for prefix in Self.sipPrefixes where appPath.hasPrefix(prefix) {
            return true
        }
        return false
    }
    /// CS_ADHOC (0x2) — signed without a real certificate identity
    private static let csAdhoc: UInt32 = 0x2
    /// CS_RUNTIME (0x10000) — hardened runtime flag from <Security/CSCommon.h>
    private static let csRuntime: UInt32 = 0x10000
    /// CS_REQUIRE_LV (0x2000) — require library validation flag
    private static let csRequireLV: UInt32 = 0x2000

    /// Analyzes the code signing metadata for the app bundle at `appPath`.
    /// Returns a default "unsigned" CodeSigningInfo (with analysisError=true) if extraction fails.
    func analyze(appPath: String) -> CodeSigningInfo {
        let url = URL(fileURLWithPath: appPath) as CFURL
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url, SecCSFlags(rawValue: 0), &staticCode) == errSecSuccess,
              let code = staticCode else {
            return CodeSigningInfo(
                signed: false, teamId: nil, signingIdentifier: nil,
                hardenedRuntime: false, libraryValidationFlag: false, analysisError: true,
                isAdhoc: false, certificateChain: []
            )
        }

        var cfInfo: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: 0x2), &cfInfo) == errSecSuccess,
              let info = cfInfo as? [String: Any] else {
            return CodeSigningInfo(
                signed: false, teamId: nil, signingIdentifier: nil,
                hardenedRuntime: false, libraryValidationFlag: false, analysisError: true,
                isAdhoc: false, certificateChain: []
            )
        }

        return codeSigningInfo(from: info)
    }

    func codeSigningInfo(from info: [String: Any]) -> CodeSigningInfo {
        let teamId = info[kSecCodeInfoTeamIdentifier as String] as? String
        let signingIdentifier = info[kSecCodeInfoIdentifier as String] as? String

        var codeFlags: UInt32 = 0
        if let n = info[kSecCodeInfoFlags as String] as? NSNumber {
            codeFlags = n.uint32Value
        }

        let chain = extractCertificateChain(from: info)

        return CodeSigningInfo(
            signed: signingIdentifier != nil,
            teamId: teamId,
            signingIdentifier: signingIdentifier,
            hardenedRuntime: (codeFlags & Self.csRuntime) != 0,
            libraryValidationFlag: (codeFlags & Self.csRequireLV) != 0,
            analysisError: false,
            isAdhoc: (codeFlags & Self.csAdhoc) != 0,
            certificateChain: chain
        )
    }

    /// Extract the certificate chain from signing information.
    ///
    /// Reads `kSecCodeInfoCertificates`, then for each SecCertificate extracts:
    /// - Common name via `SecCertificateCopySubjectSummary()`
    /// - SHA-256 fingerprint of the DER-encoded certificate
    /// - Validity dates via `SecCertificateCopyValues()`
    /// - Organization from the subject OID
    ///
    /// Returns an empty array on failure (graceful degradation).
    private func extractCertificateChain(from info: [String: Any]) -> [CertificateDetail] {
        guard let certs = info[kSecCodeInfoCertificates as String] as? [SecCertificate],
              !certs.isEmpty else {
            return []
        }

        let dateFormatter = ISO8601DateFormatter()
        return certs.enumerated().compactMap { index, cert in
            certificateDetail(
                for: cert,
                index: index,
                chainCount: certs.count,
                dateFormatter: dateFormatter
            )
        }
    }

    private func certificateDetail(
        for cert: SecCertificate,
        index: Int,
        chainCount: Int,
        dateFormatter: ISO8601DateFormatter
    ) -> CertificateDetail {
        let values = SecCertificateCopyValues(cert, nil, nil) as? [String: Any]

        return CertificateDetail(
            commonName: SecCertificateCopySubjectSummary(cert) as String?,
            organization: certificateOrganization(from: values),
            sha256: certificateFingerprint(cert),
            validFrom: certificateDate(
                from: values,
                oid: kSecOIDX509V1ValidityNotBefore as String,
                dateFormatter: dateFormatter
            ),
            validTo: certificateDate(
                from: values,
                oid: kSecOIDX509V1ValidityNotAfter as String,
                dateFormatter: dateFormatter
            ),
            isRoot: index == chainCount - 1
        )
    }

    private func certificateFingerprint(_ cert: SecCertificate) -> String {
        let derData = SecCertificateCopyData(cert) as Data
        let digest = SHA256.hash(data: derData)
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    private func certificateDate(
        from values: [String: Any]?,
        oid: String,
        dateFormatter: ISO8601DateFormatter
    ) -> String? {
        guard let dateValue = certificateValue(from: values, oid: oid) as? NSNumber else {
            return nil
        }
        let date = Date(timeIntervalSinceReferenceDate: dateValue.doubleValue)
        return dateFormatter.string(from: date)
    }

    private func certificateValue(from values: [String: Any]?, oid: String) -> Any? {
        let property = values?[oid] as? [String: Any]
        return property?[kSecPropertyKeyValue as String]
    }

    private func certificateOrganization(from values: [String: Any]?) -> String? {
        guard let subject = values?[kSecOIDX509V1SubjectName as String] as? [String: Any],
              let sectionItems = subject[kSecPropertyKeyValue as String] as? [[String: Any]] else {
            return nil
        }
        return sectionItems.compactMap(certificateOrganizationValue).first
    }

    private func certificateOrganizationValue(from item: [String: Any]) -> String? {
        guard let label = item[kSecPropertyKeyLabel as String] as? String,
              label == "2.5.4.10" else {
            return nil
        }
        return item[kSecPropertyKeyValue as String] as? String
    }
}
