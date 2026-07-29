import Foundation
import RootstockCore

/// Wave-13 compound: ScreenCapture privacy dual-use × remote/FDA path-to-impact.
public struct ScreenCaptureFdaCompoundVector: Check {
    public static let id = "rootstock.vector.data.screencapture_fda_compound"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.screenCapturePrivacyDualUse
        let a = s?.screencaptureToolPaths.count ?? 0
        let b = s?.screenCaptureKitPaths.count ?? 0
        guard a >= 1, b >= 1 || a >= 2 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        guard compound.hasAmplifier || a + b >= 3 else { return [] }
        var evidence: [Evidence] = [
            Evidence(type: "screencapture_compound", detail: "a=\(a) b=\(b) remote=\(compound.remote) fda=\(compound.fullDiskAccess) sensorThin=\(compound.sensorThin)"),
        ]
        if let s {
            for path in (s.screencaptureToolPaths + s.screenCaptureKitPaths).prefix(8) {
                evidence.append(Evidence(type: "compound_path", path: path, detail: "ScreenCapture privacy dual-use compound"))
            }
        }
        evidence.append(Evidence(type: "honesty", detail: "never captures screens or dumps Screen Recording TCC rows."))
        let severity = compound.severity
        return [Finding(id: Self.id, title: compound.remote ? "ScreenCapture privacy dual-use × remote compound" : "ScreenCapture privacy dual-use × impact compound", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1113", "T1125", "T1005"], remediation: [
                "Prioritize hosts co-locating ScreenCapture privacy dual-use with remote/FDA amplifiers",
                "Use Wave-13 lab plans under ROE for purple validation",
                "OPSEC: path-to-impact ranking only - not an auto-exploit chain",
            ], falsePositiveNotes: "Developer hosts may co-locate dual-use paths; rank production remote hosts first."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 27, esfExpected: ["OPEN", "EXEC", "READ"]))]
    }
}
