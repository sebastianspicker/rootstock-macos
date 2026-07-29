import Foundation
import Security
import os.log
import Models

/// Entitlement extraction result with explicit uncertainty.
public struct EntitlementExtractionResult {
    public let entitlements: [String: Any]
    public let available: Bool
    public let errorMessage: String?
}

/// Extracts the entitlements dictionary from a signed executable.
///
/// Primary method: Security.framework `SecCodeCopySigningInformation`
/// Fallback: `codesign -d --entitlements :- <path>` CLI output parsed as plist
public struct EntitlementExtractor: Sendable {

    private static let logger = Logger(subsystem: "com.rootstock.collector", category: "EntitlementExtractor")

    public init() { }

    /// Returns entitlements plus an availability flag so extraction failure
    /// cannot be confused with a valid empty entitlement set.
    public func extract(from executableURL: URL) -> EntitlementExtractionResult {
        if let result = extractWithSecurityFramework(url: executableURL) {
            return EntitlementExtractionResult(
                entitlements: result,
                available: true,
                errorMessage: nil
            )
        }
        Self.logger.debug("Security.framework extraction failed for \(executableURL.path, privacy: .private(mask: .hash)), falling back to codesign CLI")
        if let result = extractWithCodesignCLI(path: executableURL.path) {
            return EntitlementExtractionResult(
                entitlements: result,
                available: true,
                errorMessage: nil
            )
        }
        return EntitlementExtractionResult(
            entitlements: [:],
            available: false,
            errorMessage: "Security.framework and codesign entitlement extraction failed"
        )
    }

    // MARK: - Security.framework (primary)

    private func extractWithSecurityFramework(url: URL) -> [String: Any]? {
        var staticCode: SecStaticCode?
        let createStatus = SecStaticCodeCreateWithPath(
            url as CFURL, SecCSFlags(rawValue: 0), &staticCode
        )
        guard createStatus == errSecSuccess, let code = staticCode else {
            Self.logger.debug("SecStaticCodeCreateWithPath failed (status \(createStatus)) for \(url.path, privacy: .private(mask: .hash))")
            return nil
        }

        // Swift bridges SecCodeCopySigningInformation to take SecStaticCode directly.
        // kSecCSSigningInformation (0x2) makes kSecCodeInfoEntitlementsDict available.
        var cfInfo: CFDictionary?
        let copyStatus = SecCodeCopySigningInformation(code, SecCSFlags(rawValue: 0x2), &cfInfo)
        guard copyStatus == errSecSuccess,
              let info = cfInfo as? [String: Any] else {
            Self.logger.debug("SecCodeCopySigningInformation failed (status \(copyStatus)) for \(url.path, privacy: .private(mask: .hash))")
            return nil
        }

        return info[kSecCodeInfoEntitlementsDict as String] as? [String: Any]
    }

    // MARK: - codesign CLI (fallback)

    private func extractWithCodesignCLI(path: String) -> [String: Any]? {
        guard let result = Shell.runProcess(
            "/usr/bin/codesign",
            ["-d", "--entitlements", ":-", path],
            timeoutSeconds: 10
        ), result.terminationStatus == 0, !result.timedOut else {
            return nil
        }

        let data = Data(result.stdout.utf8)
        guard !data.isEmpty else { return nil }

        var format = PropertyListSerialization.PropertyListFormat.xml
        return try? PropertyListSerialization.propertyList(
            from: data, options: [], format: &format
        ) as? [String: Any]
    }
}
