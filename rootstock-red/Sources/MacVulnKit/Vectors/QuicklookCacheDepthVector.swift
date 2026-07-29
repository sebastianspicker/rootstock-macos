import Foundation
import RootstockCore

/// Path-to-impact: QuickLook thumbnail cache residual depth.
public struct QuicklookCacheDepthVector: Check {
    public static let id = "rootstock.vector.data.quicklook_cache_depth"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.quicklookCacheDepth
        let a = s?.quicklookDaemonPaths.count ?? 0
        let b = s?.thumbnailCachePaths.count ?? 0
        let c = s?.qlmanagePaths.count ?? 0
        let surface = s?.quicklookSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.quicklook_cache_depth"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        var evidence: [Evidence] = [
            Evidence(type: "quicklook_cache_depth_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(compound.remote) fda=\(compound.fullDiskAccess)"),
        ]
        if let s {
            evidence += VectorEvidence.paths(s.quicklookDaemonPaths + s.thumbnailCachePaths + s.qlmanagePaths, type: "quicklook_cache_depth_path", detail: "QuickLook cache depth path", limit: 12)
            evidence += VectorEvidence.notes(s.notes, type: "quicklook_cache_depth_note", limit: 5)
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never dumps QuickLook thumbnail bitmap contents as secret material."))
        let severity = compound.surfaceSeverity(pathPairCount: a + b)
        return [Finding(id: Self.id, title: compound.remote ? "QuickLook cache depth with remote amplifier" : "QuickLook thumbnail cache residual depth", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1005", "T1083", "T1552"], remediation: [
                "Inventory and baseline QuickLook cache depth paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never dumps QuickLook thumbnail bitmap contents as secret material",
            ], falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]))]
    }
}
