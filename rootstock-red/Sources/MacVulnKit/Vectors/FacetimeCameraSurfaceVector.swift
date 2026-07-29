import Foundation
import RootstockCore

/// Path-to-impact: FaceTime / camera pipeline dual-use surface.
public struct FacetimeCameraSurfaceVector: Check {
    public static let id = "rootstock.vector.data.facetime_camera_surface"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.facetimeCameraSurface
        let a = s?.facetimeAppPaths.count ?? 0
        let b = s?.avConferencePaths.count ?? 0
        let c = s?.facetimePrefPaths.count ?? 0
        let surface = s?.facetimeSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.facetime_camera_surface"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        var evidence: [Evidence] = [
            Evidence(type: "facetime_camera_surface_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(compound.remote) fda=\(compound.fullDiskAccess)"),
        ]
        if let s {
            evidence += VectorEvidence.paths(s.facetimeAppPaths + s.avConferencePaths + s.facetimePrefPaths, type: "facetime_camera_surface_path", detail: "FaceTime camera dual-use path", limit: 10)
            evidence += VectorEvidence.notes(s.notes, type: "facetime_camera_surface_note", limit: 4)
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never activates camera/mic or dumps FaceTime call history contents."))
        let severity = compound.surfaceSeverity(pathPairCount: a + b)
        return [Finding(id: Self.id, title: compound.remote ? "FaceTime camera dual-use with remote amplifier" : "FaceTime / camera pipeline dual-use surface", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1125", "T1123", "T1113"], remediation: [
                "Inventory and baseline FaceTime camera dual-use paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never activates camera/mic or dumps FaceTime call history contents",
            ], falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]))]
    }
}
