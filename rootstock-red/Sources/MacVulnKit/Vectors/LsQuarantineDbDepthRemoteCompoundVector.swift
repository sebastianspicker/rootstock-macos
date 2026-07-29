import Foundation
import RootstockCore

/// Wave-14 compound: LS QuarantineEvents depth × remote/FDA path-to-impact.
public struct LsQuarantineDbDepthRemoteCompoundVector: Check {
    public static let id = "rootstock.vector.codesign.ls_quarantine_db_depth_remote_compound"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.lsQuarantineDbDepth
        let a = s?.quarantineDbPaths.count ?? 0
        let b = s?.lsSupportPaths.count ?? 0
        guard a >= 1, b >= 1 || a >= 2 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        guard compound.hasAmplifier || a + b >= 3 else { return [] }
        var evidence: [Evidence] = [
            Evidence(type: "ls_quarantine_db_depth_compound", detail: "a=\(a) b=\(b) remote=\(compound.remote) fda=\(compound.fullDiskAccess) sensorThin=\(compound.sensorThin)"),
        ]
        if let s {
            for path in (s.quarantineDbPaths + s.lsSupportPaths).prefix(8) {
                evidence.append(Evidence(type: "compound_path", path: path, detail: "LS QuarantineEvents depth compound"))
            }
        }
        evidence.append(Evidence(type: "honesty", detail: "never deletes QuarantineEvents rows or clears LS quarantine history."))
        let severity = compound.severity
        return [Finding(id: Self.id, title: compound.remote ? "LS QuarantineEvents depth × remote compound" : "LS QuarantineEvents depth × impact compound", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1553.001", "T1074", "T1083"], remediation: [
                "Prioritize hosts co-locating LS QuarantineEvents depth with remote/FDA amplifiers",
                "Use Wave-14 lab plans under ROE for purple validation",
                "OPSEC: path-to-impact ranking only - not an auto-exploit chain",
            ], falsePositiveNotes: "Developer hosts may co-locate dual-use paths; rank production remote hosts first."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 27, esfExpected: ["OPEN", "EXEC", "READ"]))]
    }
}
