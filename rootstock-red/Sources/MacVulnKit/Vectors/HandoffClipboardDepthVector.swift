import Foundation
import RootstockCore

/// Path-to-impact: Handoff / Universal Clipboard residual depth.
public struct HandoffClipboardDepthVector: Check {
    public static let id = "rootstock.vector.data.handoff_clipboard_depth"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.handoffClipboardDepth
        let a = s?.handoffFrameworkPaths.count ?? 0
        let b = s?.clipboardPathHits.count ?? 0
        let c = s?.sharingdPaths.count ?? 0
        let surface = s?.handoffSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.handoff_clipboard_depth"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        var evidence: [Evidence] = [
            Evidence(type: "handoff_clipboard_depth_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(compound.remote) fda=\(compound.fullDiskAccess)"),
        ]
        if let s {
            evidence += VectorEvidence.paths(s.handoffFrameworkPaths + s.clipboardPathHits + s.sharingdPaths, type: "handoff_clipboard_depth_path", detail: "Handoff clipboard depth path", limit: 10)
            evidence += VectorEvidence.notes(s.notes, type: "handoff_clipboard_depth_note", limit: 4)
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never reads Universal Clipboard contents or forges Handoff activity."))
        let severity = compound.surfaceSeverity(pathPairCount: a + b)
        return [Finding(id: Self.id, title: compound.remote ? "Handoff clipboard depth with remote amplifier" : "Handoff / Universal Clipboard residual depth", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1115", "T1020", "T1005"], remediation: [
                "Inventory and baseline Handoff clipboard depth paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never reads Universal Clipboard contents or forges Handoff activity",
            ], falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]))]
    }
}
