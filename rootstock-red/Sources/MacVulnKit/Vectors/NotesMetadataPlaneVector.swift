import Foundation
import RootstockCore

/// Path-to-impact: Notes.app metadata collection path plane.
public struct NotesMetadataPlaneVector: Check {
    public static let id = "rootstock.vector.data.notes_metadata_plane"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.notesMetadataPlane
        let a = s?.notesAppPaths.count ?? 0
        let b = s?.notesStorePaths.count ?? 0
        let c = s?.notesContainerPaths.count ?? 0
        let surface = s?.notesSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.notes_metadata_plane"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        var evidence: [Evidence] = [
            Evidence(type: "notes_metadata_plane_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(compound.remote) fda=\(compound.fullDiskAccess)"),
        ]
        if let s {
            evidence += VectorEvidence.paths(s.notesAppPaths + s.notesStorePaths + s.notesContainerPaths, type: "notes_metadata_plane_path", detail: "Notes metadata plane path", limit: 12)
            evidence += VectorEvidence.notes(s.notes, type: "notes_metadata_plane_note", limit: 5)
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never reads Notes body contents or exports note secrets."))
        let severity = compound.surfaceSeverity(pathPairCount: a + b)
        return [Finding(id: Self.id, title: compound.remote ? "Notes metadata plane with remote amplifier" : "Notes.app metadata collection path plane", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1005", "T1114", "T1552"], remediation: [
                "Inventory and baseline Notes metadata plane paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never reads Notes body contents or exports note secrets",
            ], falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]))]
    }
}
