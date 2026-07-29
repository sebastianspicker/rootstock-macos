import Foundation
import RootstockCore

/// Path-to-impact: Podcasts library path residual.
public struct PodcastsPathPlaneVector: Check {
    public static let id = "rootstock.vector.data.podcasts_path_plane"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.podcastsPathPlane
        let a = s?.podcastsAppPaths.count ?? 0
        let b = s?.podcastsStorePaths.count ?? 0
        let c = s?.podcastsPrefPaths.count ?? 0
        let surface = s?.podcastsSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.podcasts_path_plane"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        var evidence: [Evidence] = [
            Evidence(type: "podcasts_path_plane_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(compound.remote) fda=\(compound.fullDiskAccess)"),
        ]
        if let s {
            evidence += VectorEvidence.paths(s.podcastsAppPaths + s.podcastsStorePaths + s.podcastsPrefPaths, type: "podcasts_path_plane_path", detail: "Podcasts path plane path", limit: 10)
            evidence += VectorEvidence.notes(s.notes, type: "podcasts_path_plane_note", limit: 4)
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never dumps podcast episode files or account tokens."))
        let severity = compound.surfaceSeverity(pathPairCount: a + b)
        return [Finding(id: Self.id, title: compound.remote ? "Podcasts path plane with remote amplifier" : "Podcasts library path residual", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1005", "T1083", "T1119"], remediation: [
                "Inventory and baseline Podcasts path plane paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never dumps podcast episode files or account tokens",
            ], falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]))]
    }
}
