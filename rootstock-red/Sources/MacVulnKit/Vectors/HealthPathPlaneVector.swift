import Foundation
import RootstockCore

/// Path-to-impact: Health app residual path plane.
public struct HealthPathPlaneVector: Check {
    public static let id = "rootstock.vector.data.health_path_plane"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.healthPathPlane
        let a = s?.healthAppPaths.count ?? 0
        let b = s?.healthStorePaths.count ?? 0
        let c = s?.healthdPaths.count ?? 0
        let surface = s?.healthSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.health_path_plane"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        var evidence: [Evidence] = [
            Evidence(type: "health_path_plane_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(compound.remote) fda=\(compound.fullDiskAccess)"),
        ]
        if let s {
            evidence += VectorEvidence.paths(s.healthAppPaths + s.healthStorePaths + s.healthdPaths, type: "health_path_plane_path", detail: "Health path plane path", limit: 10)
            evidence += VectorEvidence.notes(s.notes, type: "health_path_plane_note", limit: 4)
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never exports HealthKit samples or medical records."))
        let severity = compound.surfaceSeverity(pathPairCount: a + b)
        return [Finding(id: Self.id, title: compound.remote ? "Health path plane with remote amplifier" : "Health app residual path plane", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1005", "T1083", "T1213"], remediation: [
                "Inventory and baseline Health path plane paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never exports HealthKit samples or medical records",
            ], falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]))]
    }
}
