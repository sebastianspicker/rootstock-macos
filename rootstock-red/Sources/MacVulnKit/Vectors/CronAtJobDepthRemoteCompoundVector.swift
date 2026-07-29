import Foundation
import RootstockCore

/// Wave-14 compound: Cron/at job depth × remote/FDA path-to-impact.
public struct CronAtJobDepthRemoteCompoundVector: Check {
    public static let id = "rootstock.vector.persist.cron_at_job_depth_remote_compound"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.cronAtJobDepth
        let a = s?.cronBinaryPaths.count ?? 0
        let b = s?.crontabPaths.count ?? 0
        guard a >= 1, b >= 1 || a >= 2 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        guard compound.hasAmplifier || a + b >= 3 else { return [] }
        var evidence: [Evidence] = [
            Evidence(type: "cron_at_job_depth_compound", detail: "a=\(a) b=\(b) remote=\(compound.remote) fda=\(compound.fullDiskAccess) sensorThin=\(compound.sensorThin)"),
        ]
        if let s {
            for path in (s.cronBinaryPaths + s.crontabPaths).prefix(8) {
                evidence.append(Evidence(type: "compound_path", path: path, detail: "Cron/at job depth compound"))
            }
        }
        evidence.append(Evidence(type: "honesty", detail: "never installs cron or at jobs outside the lab root."))
        let severity = compound.severity
        return [Finding(id: Self.id, title: compound.remote ? "Cron/at job depth × remote compound" : "Cron/at job depth × impact compound", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1053.003", "T1053", "T1543"], remediation: [
                "Prioritize hosts co-locating Cron/at job depth with remote/FDA amplifiers",
                "Use Wave-14 lab plans under ROE for purple validation",
                "OPSEC: path-to-impact ranking only - not an auto-exploit chain",
            ], falsePositiveNotes: "Developer hosts may co-locate dual-use paths; rank production remote hosts first."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 27, esfExpected: ["OPEN", "EXEC", "READ"]))]
    }
}
