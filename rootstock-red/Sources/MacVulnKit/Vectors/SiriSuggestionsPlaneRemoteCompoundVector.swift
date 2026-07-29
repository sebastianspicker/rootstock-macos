import Foundation
import RootstockCore

/// Wave-16 compound: Siri Suggestions residual × remote/FDA path-to-impact.
public struct SiriSuggestionsPlaneRemoteCompoundVector: Check {
    public static let id = "rootstock.vector.data.siri_suggestions_plane_remote_compound"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.siriSuggestionsPlane
        let a = s?.siriFrameworkPaths.count ?? 0
        let b = s?.suggestionsStorePaths.count ?? 0
        guard a >= 1, b >= 1 || a >= 2 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        guard compound.hasAmplifier || a + b >= 3 else { return [] }
        var evidence: [Evidence] = [
            Evidence(type: "siri_suggestions_plane_compound", detail: "a=\(a) b=\(b) remote=\(compound.remote) fda=\(compound.fullDiskAccess) sensorThin=\(compound.sensorThin)"),
        ]
        if let s {
            for path in (s.siriFrameworkPaths + s.suggestionsStorePaths).prefix(6) {
                evidence.append(Evidence(type: "compound_path", path: path, detail: "Siri Suggestions residual compound"))
            }
        }
        evidence.append(Evidence(type: "honesty", detail: "never dumps Siri transcripts or Suggestions databases contents."))
        let severity = compound.severity
        return [Finding(id: Self.id, title: compound.remote ? "Siri Suggestions residual × remote compound" : "Siri Suggestions residual × impact compound", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1005", "T1083", "T1213"], remediation: [
                "Prioritize hosts co-locating Siri Suggestions residual with remote/FDA amplifiers",
                "Use Wave-16 lab plans under ROE for purple validation",
                "OPSEC: path-to-impact ranking only - not an auto-exploit chain",
            ], falsePositiveNotes: "Developer hosts may co-locate dual-use paths; rank production remote hosts first."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 27, esfExpected: ["OPEN", "EXEC", "READ"]))]
    }
}
