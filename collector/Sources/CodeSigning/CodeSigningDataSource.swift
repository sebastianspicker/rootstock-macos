import Foundation
import Models

/// Enriches Application objects with code signing metadata and injection assessment.
///
/// This is not a standalone DataSource — it enriches Application objects produced by
/// EntitlementDataSource, filling in team_id, hardened_runtime, library_validation,
/// signed, code_signing_analysis_error, and injection_methods fields.
public struct CodeSigningDataSource {
    private let analyzer = CodeSigningAnalyzer()
    private let assessment = InjectionAssessment()

    public init() {}

    /// Enriches the given Application array in place with code signing metadata.
    ///
    /// For each app, runs Security.framework analysis and injection assessment.
    /// If analysis fails, signing posture stays unknown and an error is recorded.
    ///
    /// - Returns: Per-app `CollectionError` entries for any analysis failures.
    @discardableResult
    public func enrich(applications: inout [Application]) -> [CollectionError] {
        let (enrichedApplications, errors) = enriched(applications: applications)
        applications = enrichedApplications
        return errors
    }

    /// Return a new array enriched with code signing metadata.
    ///
    /// This mirrors the copy-on-return pattern used by Sandbox and Quarantine
    /// so orchestrator phases can pass explicit immutable stage outputs.
    public func enriched(applications: [Application]) -> ([Application], [CollectionError]) {
        var errors: [CollectionError] = []
        let enrichedApplications = applications.map { app in
            let enriched = enrich(application: app)
            errors.append(contentsOf: enriched.errors)
            return enriched.application
        }

        return (enrichedApplications, errors)
    }

    private func enrich(application app: Application) -> (
        application: Application,
        errors: [CollectionError]
    ) {
        let resolvedPath = URL(fileURLWithPath: app.path).resolvingSymlinksInPath().path
        let info = analyzer.analyze(appPath: resolvedPath)
        let sipProtected = analyzer.isSIPProtected(appPath: resolvedPath)
        let analysisFailed = info.analysisError
        let canAssessInjection = !analysisFailed && app.entitlementsAvailable
        let assessmentResult = canAssessInjection ? assessment.assess(
            signingInfo: info,
            entitlements: app.entitlements,
            isElectron: app.isElectron,
            isSipProtected: sipProtected
        ) : nil
        let errors = analysisFailed ? [analysisError(for: app)] : []

        return (
            application: makeApplication(
                from: app,
                signingInfo: info,
                assessmentResult: assessmentResult,
                resolvedPath: resolvedPath,
                sipProtected: sipProtected
            ),
            errors: errors
        )
    }

    private func makeApplication(
        from app: Application,
        signingInfo info: CodeSigningInfo,
        assessmentResult: InjectionAssessmentResult?,
        resolvedPath: String,
        sipProtected: Bool
    ) -> Application {
        let analysisFailed = info.analysisError

        return Application(
            identity: Application.Identity(
                name: app.name,
                bundleId: app.bundleId,
                path: app.path,
                version: app.version
            ),
            flags: Application.Flags(isElectron: app.isElectron, isSystem: app.isSystem),
            signing: signingState(
                from: app,
                signingInfo: info,
                assessmentResult: assessmentResult,
                resolvedPath: resolvedPath
            ),
            security: securityState(from: app, sipProtected: sipProtected),
            entitlementState: entitlementState(
                from: app,
                signingInfo: info,
                assessmentResult: assessmentResult,
                resolvedPath: resolvedPath,
                analysisFailed: analysisFailed
            )
        )
    }

    private func signingState(
        from app: Application,
        signingInfo info: CodeSigningInfo,
        assessmentResult: InjectionAssessmentResult?,
        resolvedPath: String
    ) -> Application.Signing {
        let analysisFailed = info.analysisError
        let chain = info.certificateChain
        let leafCert = chain.first

        return Application.Signing(
            teamId: info.teamId,
            hardenedRuntime: analysisFailed ? nil : info.hardenedRuntime,
            libraryValidation: app.entitlementsAvailable ? assessmentResult?.effectiveLibraryValidation : nil,
            signed: analysisFailed ? nil : info.signed,
            analysis: Application.SigningAnalysis(
                codeSigningAnalysisError: analysisFailed,
                isNotarized: notarizationStatus(appPath: resolvedPath, app: app, signingInfo: info),
                isAdhocSigned: analysisFailed ? false : info.isAdhoc
            ),
            certificate: Application.CertificateState(
                signingCertificateCN: leafCert?.commonName,
                signingCertificateSHA256: leafCert?.sha256,
                certificateExpires: leafCert?.validTo,
                isCertificateExpired: isExpired(certificate: leafCert),
                certificateChainLength: chain.isEmpty ? nil : chain.count,
                certificateTrustValid: nil,
                certificateChain: chain
            )
        )
    }

    private func securityState(from app: Application, sipProtected: Bool) -> Application.Security {
        Application.Security(
            isSipProtected: sipProtected,
            isSandboxed: app.isSandboxed,
            sandboxExceptions: app.sandboxExceptions
        )
    }

    private func entitlementState(
        from app: Application,
        signingInfo info: CodeSigningInfo,
        assessmentResult: InjectionAssessmentResult?,
        resolvedPath: String,
        analysisFailed: Bool
    ) -> Application.EntitlementState {
        Application.EntitlementState(
            entitlementsAvailable: app.entitlementsAvailable,
            entitlementExtractionError: app.entitlementExtractionError,
            entitlements: app.entitlements,
            injectionMethods: assessmentResult?.methods ?? [],
            launchConstraintCategory: analysisFailed ? nil : detectLaunchConstraint(
                appPath: resolvedPath,
                signed: info.signed,
                isSystem: app.isSystem
            )
        )
    }

    private func analysisError(for app: Application) -> CollectionError {
        CollectionError(
            source: "CodeSigning",
            message: "Failed to analyze code signature for \(app.bundleId)",
            recoverable: true
        )
    }

    private func notarizationStatus(
        appPath: String,
        app: Application,
        signingInfo info: CodeSigningInfo
    ) -> Bool? {
        guard !info.analysisError && !app.isSystem && info.signed else { return nil }
        return checkNotarization(appPath: appPath)
    }

    private func isExpired(certificate: CertificateDetail?) -> Bool {
        guard let expiry = certificate?.validTo,
              let date = ISO8601DateFormatter().date(from: expiry) else { return false }
        return date < Date()
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
