import Foundation
import RootstockCore

/// Path-to-impact: Screen Sharing / ARD residual depth.
public struct ScreenSharingArdDepthVector: Check {
    public static let id = "rootstock.vector.network.screen_sharing_ard_depth"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.screenSharingArdDepth
        let a = s?.screenSharingAppPaths.count ?? 0
        let b = s?.ardAgentPaths.count ?? 0
        let c = s?.remoteMgmtPrefPaths.count ?? 0
        let surface = s?.ardSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.screen_sharing_ard_depth"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        var evidence: [Evidence] = [
            Evidence(type: "screen_sharing_ard_depth_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(compound.remote) fda=\(compound.fullDiskAccess)"),
        ]
        if let s {
            evidence += VectorEvidence.paths(s.screenSharingAppPaths + s.ardAgentPaths + s.remoteMgmtPrefPaths, type: "screen_sharing_ard_depth_path", detail: "Screen Sharing ARD depth path", limit: 12)
            evidence += VectorEvidence.notes(s.notes, type: "screen_sharing_ard_depth_note", limit: 5)
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never enables Screen Sharing or ARD, never connects to remote desktops."))
        let severity = compound.surfaceSeverity(pathPairCount: a + b)
        return [Finding(id: Self.id, title: compound.remote ? "Screen Sharing ARD depth with remote amplifier" : "Screen Sharing / ARD residual depth", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1021", "T1219", "T1133"], remediation: [
                "Inventory and baseline Screen Sharing ARD depth paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never enables Screen Sharing or ARD, never connects to remote desktops",
            ], falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]))]
    }
}
