import Foundation
import RootstockCore

/// Path-to-impact: LaunchServices QuarantineEvents DB residual depth.
public struct LsQuarantineDbDepthVector: Check {
    public static let id = "rootstock.vector.codesign.ls_quarantine_db_depth"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.lsQuarantineDbDepth
        let a = s?.quarantineDbPaths.count ?? 0
        let b = s?.lsSupportPaths.count ?? 0
        let c = s?.quarantineToolHints.count ?? 0
        let surface = s?.quarantineDbSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.ls_quarantine_db_depth"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        var evidence: [Evidence] = [
            Evidence(type: "ls_quarantine_db_depth_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(compound.remote) fda=\(compound.fullDiskAccess)"),
        ]
        if let s {
            evidence += VectorEvidence.paths(s.quarantineDbPaths + s.lsSupportPaths + s.quarantineToolHints, type: "ls_quarantine_db_depth_path", detail: "LS QuarantineEvents depth path", limit: 12)
            evidence += VectorEvidence.notes(s.notes, type: "ls_quarantine_db_depth_note", limit: 5)
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never deletes QuarantineEvents rows or clears LS quarantine history."))
        let severity = compound.surfaceSeverity(pathPairCount: a + b)
        return [Finding(id: Self.id, title: compound.remote ? "LS QuarantineEvents depth with remote amplifier" : "LaunchServices QuarantineEvents DB residual depth", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1553.001", "T1074", "T1083"], remediation: [
                "Inventory and baseline LS QuarantineEvents depth paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never deletes QuarantineEvents rows or clears LS quarantine history",
            ], falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]))]
    }
}
