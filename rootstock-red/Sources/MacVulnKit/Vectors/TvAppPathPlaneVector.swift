import Foundation
import RootstockCore

/// Path-to-impact: TV.app residual path plane.
public struct TvAppPathPlaneVector: Check {
    public static let id = "rootstock.vector.data.tv_app_path_plane"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.tvAppPathPlane
        let a = s?.tvAppPaths.count ?? 0
        let b = s?.tvContainerPaths.count ?? 0
        let c = s?.tvPrefPaths.count ?? 0
        let surface = s?.tvSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.tv_app_path_plane"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        var evidence: [Evidence] = [
            Evidence(type: "tv_app_path_plane_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(compound.remote) fda=\(compound.fullDiskAccess)"),
        ]
        if let s {
            evidence += VectorEvidence.paths(s.tvAppPaths + s.tvContainerPaths + s.tvPrefPaths, type: "tv_app_path_plane_path", detail: "TV.app path plane path", limit: 10)
            evidence += VectorEvidence.notes(s.notes, type: "tv_app_path_plane_note", limit: 4)
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never dumps TV.app media caches or account material."))
        let severity = compound.surfaceSeverity(pathPairCount: a + b)
        return [Finding(id: Self.id, title: compound.remote ? "TV.app path plane with remote amplifier" : "TV.app residual path plane", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1005", "T1083", "T1119"], remediation: [
                "Inventory and baseline TV.app path plane paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never dumps TV.app media caches or account material",
            ], falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]))]
    }
}
