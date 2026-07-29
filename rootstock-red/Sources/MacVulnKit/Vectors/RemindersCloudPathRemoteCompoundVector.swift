import Foundation
import RootstockCore

/// Wave-16 compound: Reminders cloud path × remote/FDA path-to-impact.
public struct RemindersCloudPathRemoteCompoundVector: Check {
    public static let id = "rootstock.vector.data.reminders_cloud_path_remote_compound"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.remindersCloudPath
        let a = s?.remindersAppPaths.count ?? 0
        let b = s?.remindersStorePaths.count ?? 0
        guard a >= 1, b >= 1 || a >= 2 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        guard compound.hasAmplifier || a + b >= 3 else { return [] }
        var evidence: [Evidence] = [
            Evidence(type: "reminders_cloud_path_compound", detail: "a=\(a) b=\(b) remote=\(compound.remote) fda=\(compound.fullDiskAccess) sensorThin=\(compound.sensorThin)"),
        ]
        if let s {
            for path in (s.remindersAppPaths + s.remindersStorePaths).prefix(6) {
                evidence.append(Evidence(type: "compound_path", path: path, detail: "Reminders cloud path compound"))
            }
        }
        evidence.append(Evidence(type: "honesty", detail: "never reads reminder titles/bodies or exports Reminders databases."))
        let severity = compound.severity
        return [Finding(id: Self.id, title: compound.remote ? "Reminders cloud path × remote compound" : "Reminders cloud path × impact compound", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1005", "T1213", "T1083"], remediation: [
                "Prioritize hosts co-locating Reminders cloud path with remote/FDA amplifiers",
                "Use Wave-16 lab plans under ROE for purple validation",
                "OPSEC: path-to-impact ranking only - not an auto-exploit chain",
            ], falsePositiveNotes: "Developer hosts may co-locate dual-use paths; rank production remote hosts first."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 27, esfExpected: ["OPEN", "EXEC", "READ"]))]
    }
}
