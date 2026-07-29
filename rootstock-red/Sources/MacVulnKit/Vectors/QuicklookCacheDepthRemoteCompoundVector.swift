import Foundation
import RootstockCore

/// Wave-14 compound: QuickLook cache depth × remote/FDA path-to-impact.
public struct QuicklookCacheDepthRemoteCompoundVector: Check {
    public static let id = "rootstock.vector.data.quicklook_cache_depth_remote_compound"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.quicklookCacheDepth
        let a = s?.quicklookDaemonPaths.count ?? 0
        let b = s?.thumbnailCachePaths.count ?? 0
        guard a >= 1, b >= 1 || a >= 2 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        guard compound.hasAmplifier || a + b >= 3 else { return [] }
        var evidence: [Evidence] = [
            Evidence(type: "quicklook_cache_depth_compound", detail: "a=\(a) b=\(b) remote=\(compound.remote) fda=\(compound.fullDiskAccess) sensorThin=\(compound.sensorThin)"),
        ]
        if let s {
            for path in (s.quicklookDaemonPaths + s.thumbnailCachePaths).prefix(8) {
                evidence.append(Evidence(type: "compound_path", path: path, detail: "QuickLook cache depth compound"))
            }
        }
        evidence.append(Evidence(type: "honesty", detail: "never dumps QuickLook thumbnail bitmap contents as secret material."))
        let severity = compound.severity
        return [Finding(id: Self.id, title: compound.remote ? "QuickLook cache depth × remote compound" : "QuickLook cache depth × impact compound", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1005", "T1083", "T1552"], remediation: [
                "Prioritize hosts co-locating QuickLook cache depth with remote/FDA amplifiers",
                "Use Wave-14 lab plans under ROE for purple validation",
                "OPSEC: path-to-impact ranking only - not an auto-exploit chain",
            ], falsePositiveNotes: "Developer hosts may co-locate dual-use paths; rank production remote hosts first."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 27, esfExpected: ["OPEN", "EXEC", "READ"]))]
    }
}
