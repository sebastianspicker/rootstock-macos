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
        for exception in Self.sipExceptions {
            if appPath.hasPrefix(exception) { return false }
        }
        for prefix in Self.sipPrefixes {
            if appPath.hasPrefix(prefix) { return true }
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
            let commonName = SecCertificateCopySubjectSummary(cert) as String?

            let derData = SecCertificateCopyData(cert) as Data
            let digest = SHA256.hash(data: derData)
            let sha256 = digest.map { String(format: "%02x", $0) }.joined()

            let isRoot = index == certs.count - 1

            var validFrom: String?
            var validTo: String?
            var organization: String?

            if let values = SecCertificateCopyValues(cert, nil, nil) as? [String: Any] {
                // Validity period
                if let notBefore = values["2.5.4.47"] as? [String: Any] ?? values[kSecOIDX509V1ValidityNotBefore as String] as? [String: Any],
                   let val = notBefore[kSecPropertyKeyValue as String] {
                    if let num = val as? NSNumber {
                        let date = Date(timeIntervalSinceReferenceDate: num.doubleValue)
                        validFrom = dateFormatter.string(from: date)
                    }
                }
                if let notAfter = values["2.5.4.48"] as? [String: Any] ?? values[kSecOIDX509V1ValidityNotAfter as String] as? [String: Any],
                   let val = notAfter[kSecPropertyKeyValue as String] {
                    if let num = val as? NSNumber {
                        let date = Date(timeIntervalSinceReferenceDate: num.doubleValue)
                        validTo = dateFormatter.string(from: date)
                    }
                }

                // Organization from subject name
                if let subject = values[kSecOIDX509V1SubjectName as String] as? [String: Any],
                   let sectionItems = subject[kSecPropertyKeyValue as String] as? [[String: Any]] {
                    for item in sectionItems {
                        if let label = item[kSecPropertyKeyLabel as String] as? String,
                           label == "2.5.4.10",
                           let orgValue = item[kSecPropertyKeyValue as String] as? String {
                            organization = orgValue
                            break
                        }
                    }
                }
            }

            return CertificateDetail(
                commonName: commonName,
                organization: organization,
                sha256: sha256,
                validFrom: validFrom,
                validTo: validTo,
                isRoot: isRoot
            )
        }
    }
}
