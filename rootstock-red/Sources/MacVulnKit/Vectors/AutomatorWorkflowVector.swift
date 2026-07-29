import Foundation
import RootstockCore

/// Path-to-impact: Automator workflow delivery residual.
public struct AutomatorWorkflowVector: Check {
    public static let id = "rootstock.vector.delivery.automator_workflow"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.automatorWorkflow
        let a = s?.automatorAppPaths.count ?? 0
        let b = s?.workflowSamplePaths.count ?? 0
        let c = s?.actionLibraryPaths.count ?? 0
        let surface = s?.workflowSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.automator_workflow"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        var evidence: [Evidence] = [
            Evidence(type: "automator_workflow_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(compound.remote) fda=\(compound.fullDiskAccess)"),
        ]
        if let s {
            evidence += VectorEvidence.paths(s.automatorAppPaths + s.workflowSamplePaths + s.actionLibraryPaths, type: "automator_workflow_path", detail: "Automator workflow delivery path", limit: 12)
            evidence += VectorEvidence.notes(s.notes, type: "automator_workflow_note", limit: 5)
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never executes Automator workflows or plants malicious .workflow bundles."))
        let severity = compound.surfaceSeverity(pathPairCount: a + b)
        return [Finding(id: Self.id, title: compound.remote ? "Automator workflow delivery with remote amplifier" : "Automator workflow delivery residual", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1059", "T1204", "T1546"], remediation: [
                "Inventory and baseline Automator workflow delivery paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never executes Automator workflows or plants malicious .workflow bundles",
            ], falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]))]
    }
}
