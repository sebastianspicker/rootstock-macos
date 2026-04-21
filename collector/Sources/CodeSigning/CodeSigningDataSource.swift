import Foundation
import Models

/// Enriches Application objects with code signing metadata and injection assessment.
///
/// This is not a standalone DataSource — it enriches Application objects produced by
/// EntitlementDataSource, filling in team_id, hardened_runtime, library_validation,
/// signed, and injection_methods fields.
public struct CodeSigningDataSource {
    private let analyzer = CodeSigningAnalyzer()
    private let assessment = InjectionAssessment()

    public init() {}

    /// Enriches the given Application array in place with code signing metadata.
    ///
    /// For each app, runs Security.framework analysis and injection assessment.
    /// If analysis fails, `signed` is set to `false` and an error is recorded.
    ///
    /// - Returns: Per-app `CollectionError` entries for any analysis failures.
    @discardableResult
    public func enrich(applications: inout [Application]) -> [CollectionError] {
        var errors: [CollectionError] = []

        applications = applications.map { app in
            let resolvedPath = URL(fileURLWithPath: app.path).resolvingSymlinksInPath().path
            let info = analyzer.analyze(appPath: resolvedPath)
            let sipProtected = analyzer.isSIPProtected(appPath: resolvedPath)

            if info.analysisError {
                errors.append(CollectionError(
                    source: "CodeSigning",
                    message: "Failed to analyze code signature for \(app.bundleId)",
                    recoverable: true
                ))
            }

            let result = assessment.assess(
                signingInfo: info,
                entitlements: app.entitlements,
                isElectron: app.isElectron,
                isSipProtected: sipProtected
            )

            // Notarization: only check signed, non-system apps to control scan time.
            // spctl is ~100ms/app; unsigned apps can't be notarized by definition.
            let isNotarized: Bool?
            if !app.isSystem && info.signed {
                isNotarized = checkNotarization(appPath: resolvedPath)
            } else {
                isNotarized = nil
            }

            let launchConstraint = detectLaunchConstraint(
                appPath: resolvedPath, signed: info.signed, isSystem: app.isSystem
            )

            let chain = info.certificateChain
            let leafCert = chain.first
            let isCertExpired: Bool = {
                guard let expiry = leafCert?.validTo,
                      let date = ISO8601DateFormatter().date(from: expiry) else { return false }
                return date < Date()
            }()

            return Application(
                name: app.name,
                bundleId: app.bundleId,
                path: app.path,
                version: app.version,
                teamId: info.teamId,
                hardenedRuntime: info.hardenedRuntime,
                libraryValidation: result.effectiveLibraryValidation,
                isElectron: app.isElectron,
                isSystem: app.isSystem,
                signed: info.signed,
                isSipProtected: sipProtected,
                isSandboxed: app.isSandboxed,
                sandboxExceptions: app.sandboxExceptions,
                isNotarized: isNotarized,
                isAdhocSigned: info.isAdhoc,
                signingCertificateCN: leafCert?.commonName,
                signingCertificateSHA256: leafCert?.sha256,
                certificateExpires: leafCert?.validTo,
                isCertificateExpired: isCertExpired,
                certificateChainLength: chain.isEmpty ? nil : chain.count,
                certificateTrustValid: nil,
                certificateChain: chain,
                entitlements: app.entitlements,
                injectionMethods: result.methods,
                launchConstraintCategory: launchConstraint
            )
        }

        return errors
    }

    /// Check if an app bundle passes Gatekeeper assessment (notarized or signed by identified developer).
    private func checkNotarization(appPath: String) -> Bool {
        Shell.succeeds("/usr/sbin/spctl", ["-a", "-vv", appPath])
    }

    /// Detect launch constraint category for an application (macOS 13+).
    ///
    /// Categories:
    /// - "apple_signed": Apple-signed system binaries (SIP-protected or in /System)
    /// - "third_party_signed": Signed third-party apps (potential trust cache members)
    /// - "unconstrained": Unsigned apps — no launch constraints possible
    ///
    /// Note: Precise launch constraint enumeration requires private APIs or
    /// `launchctl print` parsing. This heuristic classifies based on signing
    /// status and path, which covers the security-relevant categories.
    private func detectLaunchConstraint(appPath: String, signed: Bool, isSystem: Bool) -> String? {
        guard signed else { return "unconstrained" }
        if isSystem { return "apple_signed" }
        return "third_party_signed"
    }
}
