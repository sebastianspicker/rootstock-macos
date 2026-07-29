import Foundation
import RootstockCore

/// Wave-16 compound: Handoff clipboard depth × remote/FDA path-to-impact.
public struct HandoffClipboardDepthRemoteCompoundVector: Check {
    public static let id = "rootstock.vector.data.handoff_clipboard_depth_remote_compound"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.handoffClipboardDepth
        let a = s?.handoffFrameworkPaths.count ?? 0
        let b = s?.clipboardPathHits.count ?? 0
        guard a >= 1, b >= 1 || a >= 2 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        guard compound.hasAmplifier || a + b >= 3 else { return [] }
        var evidence: [Evidence] = [
            Evidence(type: "handoff_clipboard_depth_compound", detail: "a=\(a) b=\(b) remote=\(compound.remote) fda=\(compound.fullDiskAccess) sensorThin=\(compound.sensorThin)"),
        ]
        if let s {
            for path in (s.handoffFrameworkPaths + s.clipboardPathHits).prefix(6) {
                evidence.append(Evidence(type: "compound_path", path: path, detail: "Handoff clipboard depth compound"))
            }
        }
        evidence.append(Evidence(type: "honesty", detail: "never reads Universal Clipboard contents or forges Handoff activity."))
        let severity = compound.severity
        return [Finding(id: Self.id, title: compound.remote ? "Handoff clipboard depth × remote compound" : "Handoff clipboard depth × impact compound", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1115", "T1020", "T1005"], remediation: [
                "Prioritize hosts co-locating Handoff clipboard depth with remote/FDA amplifiers",
                "Use Wave-16 lab plans under ROE for purple validation",
                "OPSEC: path-to-impact ranking only - not an auto-exploit chain",
            ], falsePositiveNotes: "Developer hosts may co-locate dual-use paths; rank production remote hosts first."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 27, esfExpected: ["OPEN", "EXEC", "READ"]))]
    }
}
