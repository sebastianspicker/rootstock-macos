import Foundation
import Models

/// Enriches Application objects with code signing metadata and injection assessment.
///
/// This is not a standalone DataSource - it enriches Application objects produced by
/// EntitlementDataSource, filling in team_id, hardened_runtime, library_validation,
/// signed, code_signing_analysis_error, and injection_methods fields.
public struct CodeSigningDataSource {
    private struct DerivedApplicationState {
        let resolvedPath: String
        let sipProtected: Bool
        let isNotarized: Bool?
    }

    private let analyzer = CodeSigningAnalyzer()
    private let assessment = InjectionAssessment()
    private let runCommand: ShellCommand

    public init() {
        runCommand = { path, arguments, timeout in
            ShellCommandRunner.run(path, arguments, timeout)
        }
    }

    init(
        runCommand: @escaping ShellCommand
    ) {
        self.runCommand = runCommand
    }

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
        let notarization = notarizationStatus(
            appPath: resolvedPath,
            app: app,
            signingInfo: info
        )
        var errors = analysisFailed ? [analysisError(for: app)] : []
        if let error = notarization.error {
            errors.append(error)
        }

        return (
            application: makeApplication(
                from: app,
                signingInfo: info,
                assessmentResult: assessmentResult,
                state: DerivedApplicationState(
                    resolvedPath: resolvedPath,
                    sipProtected: sipProtected,
                    isNotarized: notarization.value
                )
            ),
            errors: errors
        )
    }

    private func makeApplication(
        from app: Application,
        signingInfo info: CodeSigningInfo,
        assessmentResult: InjectionAssessmentResult?,
        state: DerivedApplicationState
    ) -> Application {
        let analysisFailed = info.analysisError

        return app.replacing(
            signing: signingState(
                from: app,
                signingInfo: info,
                assessmentResult: assessmentResult,
                resolvedPath: state.resolvedPath,
                isNotarized: state.isNotarized
            ),
            security: securityState(from: app, sipProtected: state.sipProtected),
            entitlementState: entitlementState(
                from: app,
                signingInfo: info,
                assessmentResult: assessmentResult,
                resolvedPath: state.resolvedPath,
                analysisFailed: analysisFailed
            )
        )
    }

    private func signingState(
        from app: Application,
        signingInfo info: CodeSigningInfo,
        assessmentResult: InjectionAssessmentResult?,
        resolvedPath: String,
        isNotarized: Bool?
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
                isNotarized: isNotarized,
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
    ) -> (value: Bool?, error: CollectionError?) {
        guard !info.analysisError && !app.isSystem && info.signed else {
            return (nil, nil)
        }
        return Self.notarizationStatus(
            from: runCommand("/usr/sbin/spctl", ["-a", "-vv", appPath], 15),
            appPath: appPath
        )
    }

    private func isExpired(certificate: CertificateDetail?) -> Bool {
        guard let expiry = certificate?.validTo,
              let date = ISO8601DateFormatter().date(from: expiry) else { return false }
        return date < Date()
    }

    /// Translate Gatekeeper command state without treating infrastructure failures as rejection.
    static func notarizationStatus(
        from outcome: ShellOutcome,
        appPath: String
    ) -> (value: Bool?, error: CollectionError?) {
        switch outcome {
        case .success:
            return (true, nil)
        case .nonZeroExit:
            return (false, nil)
        case .admissionTimedOut, .launchFailed, .executionTimedOut:
            return (
                nil,
                CollectionError(
                    source: "CodeSigning",
                    message: "Notarization status unknown for \(appPath): \(outcome.failureDescription ?? "command failure")",
                    recoverable: true
                )
            )
        }
    }

    /// Detect launch constraint category for an application (macOS 13+).
    ///
    /// Categories:
    /// - "apple_signed": Apple-signed system binaries (SIP-protected or in /System)
    /// - "third_party_signed": Signed third-party apps (potential trust cache members)
    /// - "unconstrained": Unsigned apps - no launch constraints possible
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
