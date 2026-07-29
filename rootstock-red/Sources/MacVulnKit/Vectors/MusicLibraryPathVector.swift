import Foundation
import RootstockCore

/// Path-to-impact: Music / media library path residual.
public struct MusicLibraryPathVector: Check {
    public static let id = "rootstock.vector.data.music_library_path"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.musicLibraryPath
        let a = s?.musicAppPaths.count ?? 0
        let b = s?.musicLibraryPaths.count ?? 0
        let c = s?.musicPrefPaths.count ?? 0
        let surface = s?.musicSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.music_library_path"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        var evidence: [Evidence] = [
            Evidence(type: "music_library_path_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(compound.remote) fda=\(compound.fullDiskAccess)"),
        ]
        if let s {
            evidence += VectorEvidence.paths(s.musicAppPaths + s.musicLibraryPaths + s.musicPrefPaths, type: "music_library_path_path", detail: "Music library path path", limit: 10)
            evidence += VectorEvidence.notes(s.notes, type: "music_library_path_note", limit: 4)
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never exports Music library media or DRM material."))
        let severity = compound.surfaceSeverity(pathPairCount: a + b)
        return [Finding(id: Self.id, title: compound.remote ? "Music library path with remote amplifier" : "Music / media library path residual", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1005", "T1083", "T1119"], remediation: [
                "Inventory and baseline Music library path paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never exports Music library media or DRM material",
            ], falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]))]
    }
}
