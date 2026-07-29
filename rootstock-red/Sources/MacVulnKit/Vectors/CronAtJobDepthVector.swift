import Foundation
import RootstockCore

/// Path-to-impact: Cron / at job dual-use residual depth.
public struct CronAtJobDepthVector: Check {
    public static let id = "rootstock.vector.persist.cron_at_job_depth"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.cronAtJobDepth
        let a = s?.cronBinaryPaths.count ?? 0
        let b = s?.crontabPaths.count ?? 0
        let c = s?.atJobPaths.count ?? 0
        let surface = s?.cronAtSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.cron_at_job_depth"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        var evidence: [Evidence] = [
            Evidence(type: "cron_at_job_depth_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(compound.remote) fda=\(compound.fullDiskAccess)"),
        ]
        if let s {
            evidence += VectorEvidence.paths(s.cronBinaryPaths + s.crontabPaths + s.atJobPaths, type: "cron_at_job_depth_path", detail: "Cron/at job depth path", limit: 12)
            evidence += VectorEvidence.notes(s.notes, type: "cron_at_job_depth_note", limit: 5)
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never installs cron or at jobs outside the lab root."))
        let severity = compound.surfaceSeverity(pathPairCount: a + b)
        return [Finding(id: Self.id, title: compound.remote ? "Cron/at job depth with remote amplifier" : "Cron / at job dual-use residual depth", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1053.003", "T1053", "T1543"], remediation: [
                "Inventory and baseline Cron/at job depth paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never installs cron or at jobs outside the lab root",
            ], falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]))]
    }
}
