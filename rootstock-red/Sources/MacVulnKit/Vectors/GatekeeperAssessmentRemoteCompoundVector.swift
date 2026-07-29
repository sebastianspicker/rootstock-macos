import Foundation
import RootstockCore

/// Wave-13 compound: Gatekeeper assessment history × remote/FDA path-to-impact.
public struct GatekeeperAssessmentRemoteCompoundVector: Check {
    public static let id = "rootstock.vector.codesign.gk_assessment_remote_compound"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.gatekeeperAssessmentHistory
        let a = s?.syspolicydPaths.count ?? 0
        let b = s?.assessmentDbPaths.count ?? 0
        guard a >= 1, b >= 1 || a >= 2 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        guard compound.hasAmplifier || a + b >= 3 else { return [] }
        var evidence: [Evidence] = [
            Evidence(type: "gk_assessment_compound", detail: "a=\(a) b=\(b) remote=\(compound.remote) fda=\(compound.fullDiskAccess) sensorThin=\(compound.sensorThin)"),
        ]
        if let s {
            for path in (s.syspolicydPaths + s.assessmentDbPaths).prefix(8) {
                evidence.append(Evidence(type: "compound_path", path: path, detail: "Gatekeeper assessment history compound"))
            }
        }
        evidence.append(Evidence(type: "honesty", detail: "never clears Gatekeeper assessments or disables syspolicyd."))
        let severity = compound.severity
        return [Finding(id: Self.id, title: compound.remote ? "Gatekeeper assessment history × remote compound" : "Gatekeeper assessment history × impact compound", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1553.001", "T1204", "T1562"], remediation: [
                "Prioritize hosts co-locating Gatekeeper assessment history with remote/FDA amplifiers",
                "Use Wave-13 lab plans under ROE for purple validation",
                "OPSEC: path-to-impact ranking only - not an auto-exploit chain",
            ], falsePositiveNotes: "Developer hosts may co-locate dual-use paths; rank production remote hosts first."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 27, esfExpected: ["OPEN", "EXEC", "READ"]))]
    }
}
