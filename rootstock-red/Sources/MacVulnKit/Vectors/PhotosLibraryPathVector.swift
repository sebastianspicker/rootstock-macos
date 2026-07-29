import Foundation
import RootstockCore

/// Path-to-impact: Photos.app library collection path plane.
public struct PhotosLibraryPathVector: Check {
    public static let id = "rootstock.vector.data.photos_library_path"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.photosLibraryPath
        let a = s?.photosAppPaths.count ?? 0
        let b = s?.photosLibraryPaths.count ?? 0
        let c = s?.photosSupportPaths.count ?? 0
        let surface = s?.photosSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.photos_library_path"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        var evidence: [Evidence] = [
            Evidence(type: "photos_library_path_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(compound.remote) fda=\(compound.fullDiskAccess)"),
        ]
        if let s {
            evidence += VectorEvidence.paths(s.photosAppPaths + s.photosLibraryPaths + s.photosSupportPaths, type: "photos_library_path_path", detail: "Photos library path plane path", limit: 12)
            evidence += VectorEvidence.notes(s.notes, type: "photos_library_path_note", limit: 5)
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never reads photo contents or exports Photo Library media."))
        let severity = compound.surfaceSeverity(pathPairCount: a + b)
        return [Finding(id: Self.id, title: compound.remote ? "Photos library path plane with remote amplifier" : "Photos.app library collection path plane", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1005", "T1119", "T1530"], remediation: [
                "Inventory and baseline Photos library path plane paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never reads photo contents or exports Photo Library media",
            ], falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]))]
    }
}
