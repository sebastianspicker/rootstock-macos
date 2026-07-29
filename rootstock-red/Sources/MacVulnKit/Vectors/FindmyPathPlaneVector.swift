import Foundation
import RootstockCore

/// Path-to-impact: Find My residual path plane.
public struct FindmyPathPlaneVector: Check {
    public static let id = "rootstock.vector.data.findmy_path_plane"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.findmyPathPlane
        let a = s?.findMyAppPaths.count ?? 0
        let b = s?.findMyCachePaths.count ?? 0
        let c = s?.fmfdPaths.count ?? 0
        let surface = s?.findmySurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.findmy_path_plane"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        var evidence: [Evidence] = [
            Evidence(type: "findmy_path_plane_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(compound.remote) fda=\(compound.fullDiskAccess)"),
        ]
        if let s {
            evidence += VectorEvidence.paths(s.findMyAppPaths + s.findMyCachePaths + s.fmfdPaths, type: "findmy_path_plane_path", detail: "Find My path plane path", limit: 10)
            evidence += VectorEvidence.notes(s.notes, type: "findmy_path_plane_note", limit: 4)
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never queries Find My device locations or dumps owner tokens."))
        let severity = compound.surfaceSeverity(pathPairCount: a + b)
        return [Finding(id: Self.id, title: compound.remote ? "Find My path plane with remote amplifier" : "Find My residual path plane", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1011", "T1083", "T1005"], remediation: [
                "Inventory and baseline Find My path plane paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never queries Find My device locations or dumps owner tokens",
            ], falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]))]
    }
}
