import Foundation

/// Shared run context for collectors, checks, and actions.
public struct EvaluationContext: Sendable {
    public var mode: RunMode
    public var profile: ScanProfile
    public var dryRun: Bool
    public var allowNetwork: Bool
    public var consent: ConsentTokens
    public var projectDirectory: URL?
    public var hostUUID: String
    public var startedAt: Date

    public init(
        mode: RunMode = .assess,
        profile: ScanProfile = .standard,
        dryRun: Bool = true,
        allowNetwork: Bool = false,
        consent: ConsentTokens = ConsentTokens(),
        projectDirectory: URL? = nil,
        hostUUID: String = UUID().uuidString,
        startedAt: Date = Date()
    ) {
        self.mode = mode
        self.profile = profile
        self.dryRun = dryRun
        self.allowNetwork = allowNetwork
        self.consent = consent
        self.projectDirectory = projectDirectory
        self.hostUUID = hostUUID
        self.startedAt = startedAt
    }

    /// Assess-mode factory with safety defaults.
    public static func assess(
        profile: ScanProfile = .standard,
        allowNetwork: Bool = false,
        consent: ConsentTokens = ConsentTokens(),
        projectDirectory: URL? = nil
    ) -> EvaluationContext {
        EvaluationContext(
            mode: .assess,
            profile: profile,
            dryRun: true,
            allowNetwork: allowNetwork,
            consent: consent,
            projectDirectory: projectDirectory
        )
    }
}
