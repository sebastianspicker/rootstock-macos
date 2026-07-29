import Foundation
import RootstockCore

/// Wave-15 compound: Python runtime dual-use × remote/FDA path-to-impact.
public struct PythonRuntimeDualuseRemoteCompoundVector: Check {
    public static let id = "rootstock.vector.lool.python_runtime_dualuse_remote_compound"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.pythonRuntimeDualuse
        let a = s?.pythonBinaryPaths.count ?? 0
        let b = s?.sitePackagePaths.count ?? 0
        guard a >= 1, b >= 1 || a >= 2 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        guard compound.hasAmplifier || a + b >= 3 else { return [] }
        var evidence: [Evidence] = [
            Evidence(type: "python_runtime_dualuse_compound", detail: "a=\(a) b=\(b) remote=\(compound.remote) fda=\(compound.fullDiskAccess) sensorThin=\(compound.sensorThin)"),
        ]
        if let s {
            for path in (s.pythonBinaryPaths + s.sitePackagePaths).prefix(8) {
                evidence.append(Evidence(type: "compound_path", path: path, detail: "Python runtime dual-use compound"))
            }
        }
        evidence.append(Evidence(type: "honesty", detail: "never executes third-party Python payloads or drops malicious site-packages."))
        let severity = compound.severity
        return [Finding(id: Self.id, title: compound.remote ? "Python runtime dual-use × remote compound" : "Python runtime dual-use × impact compound", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1059.006", "T1059", "T1204"], remediation: [
                "Prioritize hosts co-locating Python runtime dual-use with remote/FDA amplifiers",
                "Use Wave-15 lab plans under ROE for purple validation",
                "OPSEC: path-to-impact ranking only - not an auto-exploit chain",
            ], falsePositiveNotes: "Developer hosts may co-locate dual-use paths; rank production remote hosts first."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 27, esfExpected: ["OPEN", "EXEC", "READ"]))]
    }
}
