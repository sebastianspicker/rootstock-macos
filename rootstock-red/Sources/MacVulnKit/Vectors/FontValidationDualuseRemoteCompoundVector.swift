import Foundation
import RootstockCore

/// Wave-14 compound: Font validation dual-use × remote/FDA path-to-impact.
public struct FontValidationDualuseRemoteCompoundVector: Check {
    public static let id = "rootstock.vector.delivery.font_validation_dualuse_remote_compound"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.fontValidationDualuse
        let a = s?.fontToolPaths.count ?? 0
        let b = s?.atsSupportPaths.count ?? 0
        guard a >= 1, b >= 1 || a >= 2 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        guard compound.hasAmplifier || a + b >= 3 else { return [] }
        var evidence: [Evidence] = [
            Evidence(type: "font_validation_dualuse_compound", detail: "a=\(a) b=\(b) remote=\(compound.remote) fda=\(compound.fullDiskAccess) sensorThin=\(compound.sensorThin)"),
        ]
        if let s {
            for path in (s.fontToolPaths + s.atsSupportPaths).prefix(8) {
                evidence.append(Evidence(type: "compound_path", path: path, detail: "Font validation dual-use compound"))
            }
        }
        evidence.append(Evidence(type: "honesty", detail: "never installs malicious fonts or disables font validation."))
        let severity = compound.severity
        return [Finding(id: Self.id, title: compound.remote ? "Font validation dual-use × remote compound" : "Font validation dual-use × impact compound", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1204", "T1189", "T1059"], remediation: [
                "Prioritize hosts co-locating Font validation dual-use with remote/FDA amplifiers",
                "Use Wave-14 lab plans under ROE for purple validation",
                "OPSEC: path-to-impact ranking only - not an auto-exploit chain",
            ], falsePositiveNotes: "Developer hosts may co-locate dual-use paths; rank production remote hosts first."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 27, esfExpected: ["OPEN", "EXEC", "READ"]))]
    }
}
