import Foundation
import RootstockCore

/// Wave-14 compound: Automator workflow delivery × remote/FDA path-to-impact.
public struct AutomatorWorkflowRemoteCompoundVector: Check {
    public static let id = "rootstock.vector.delivery.automator_workflow_remote_compound"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.automatorWorkflow
        let a = s?.automatorAppPaths.count ?? 0
        let b = s?.workflowSamplePaths.count ?? 0
        guard a >= 1, b >= 1 || a >= 2 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        guard compound.hasAmplifier || a + b >= 3 else { return [] }
        var evidence: [Evidence] = [
            Evidence(type: "automator_workflow_compound", detail: "a=\(a) b=\(b) remote=\(compound.remote) fda=\(compound.fullDiskAccess) sensorThin=\(compound.sensorThin)"),
        ]
        if let s {
            for path in (s.automatorAppPaths + s.workflowSamplePaths).prefix(8) {
                evidence.append(Evidence(type: "compound_path", path: path, detail: "Automator workflow delivery compound"))
            }
        }
        evidence.append(Evidence(type: "honesty", detail: "never executes Automator workflows or plants malicious .workflow bundles."))
        let severity = compound.severity
        return [Finding(id: Self.id, title: compound.remote ? "Automator workflow delivery × remote compound" : "Automator workflow delivery × impact compound", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1059", "T1204", "T1546"], remediation: [
                "Prioritize hosts co-locating Automator workflow delivery with remote/FDA amplifiers",
                "Use Wave-14 lab plans under ROE for purple validation",
                "OPSEC: path-to-impact ranking only - not an auto-exploit chain",
            ], falsePositiveNotes: "Developer hosts may co-locate dual-use paths; rank production remote hosts first."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 27, esfExpected: ["OPEN", "EXEC", "READ"]))]
    }
}
