/// Cluster/check: CredPathsCheck - multi-signal posture ranking for assess pipeline.
import Foundation
import RootstockCore

public struct CredPathsCheck: Check {
    public static let id = "rootstock.check.auth.cred_paths_present"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let existing = state.credPaths.filter(\.exists)
        guard !existing.isEmpty else { return [] }
        return [
            Finding(id: Self.id, title: "Credential-related paths present (metadata only)", severity: .info, category: .auth, resolution: .init(evidence: existing.map {
                    Evidence(type: "cred_path", path: $0.path, detail: "kind=\($0.kind)")
                }, attackTechniques: ["T1552"], remediation: [
                    "Ensure secrets are not world-readable",
                    "Rootstock Red does not read key material in assess mode",
                ]), runtime: .init(confidence: .high, dryRunSafe: true, opsecScore: 10, esfExpected: ["OPEN"])),
        ]
    }
}
