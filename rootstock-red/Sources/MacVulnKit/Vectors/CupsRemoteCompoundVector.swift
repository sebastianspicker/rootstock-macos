import Foundation
import RootstockCore

/// Wave-13 compound: CUPS printer dual-use × remote/FDA path-to-impact.
public struct CupsRemoteCompoundVector: Check {
    public static let id = "rootstock.vector.network.cups_remote_compound"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.cupsPrintDualUse
        let a = s?.cupsDaemonPaths.count ?? 0
        let b = s?.ppdConfigPaths.count ?? 0
        guard a >= 1, b >= 1 || a >= 2 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        guard compound.hasAmplifier || a + b >= 3 else { return [] }
        var evidence: [Evidence] = [
            Evidence(type: "cups_print_compound", detail: "a=\(a) b=\(b) remote=\(compound.remote) fda=\(compound.fullDiskAccess) sensorThin=\(compound.sensorThin)"),
        ]
        if let s {
            for path in (s.cupsDaemonPaths + s.ppdConfigPaths).prefix(8) {
                evidence.append(Evidence(type: "compound_path", path: path, detail: "CUPS printer dual-use compound"))
            }
        }
        evidence.append(Evidence(type: "honesty", detail: "never submits print jobs or reconfigures CUPS remotely."))
        let severity = compound.severity
        return [Finding(id: Self.id, title: compound.remote ? "CUPS printer dual-use × remote compound" : "CUPS printer dual-use × impact compound", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1040", "T1071", "T1204"], remediation: [
                "Prioritize hosts co-locating CUPS printer dual-use with remote/FDA amplifiers",
                "Use Wave-13 lab plans under ROE for purple validation",
                "OPSEC: path-to-impact ranking only - not an auto-exploit chain",
            ], falsePositiveNotes: "Developer hosts may co-locate dual-use paths; rank production remote hosts first."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 27, esfExpected: ["OPEN", "EXEC", "READ"]))]
    }
}
