import Foundation
import RootstockCore

/// Wave-16 compound: Calendar CalDAV residual × remote/FDA path-to-impact.
public struct CalendarServerPathRemoteCompoundVector: Check {
    public static let id = "rootstock.vector.data.calendar_server_path_remote_compound"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.calendarServerPath
        let a = s?.caldavFrameworkPaths.count ?? 0
        let b = s?.calendarsStorePaths.count ?? 0
        guard a >= 1, b >= 1 || a >= 2 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        guard compound.hasAmplifier || a + b >= 3 else { return [] }
        var evidence: [Evidence] = [
            Evidence(type: "calendar_server_path_compound", detail: "a=\(a) b=\(b) remote=\(compound.remote) fda=\(compound.fullDiskAccess) sensorThin=\(compound.sensorThin)"),
        ]
        if let s {
            for path in (s.caldavFrameworkPaths + s.calendarsStorePaths).prefix(6) {
                evidence.append(Evidence(type: "compound_path", path: path, detail: "Calendar CalDAV residual compound"))
            }
        }
        evidence.append(Evidence(type: "honesty", detail: "never reads calendar event bodies or credentials from CalDAV stores."))
        let severity = compound.severity
        return [Finding(id: Self.id, title: compound.remote ? "Calendar CalDAV residual × remote compound" : "Calendar CalDAV residual × impact compound", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1213", "T1005", "T1071"], remediation: [
                "Prioritize hosts co-locating Calendar CalDAV residual with remote/FDA amplifiers",
                "Use Wave-16 lab plans under ROE for purple validation",
                "OPSEC: path-to-impact ranking only - not an auto-exploit chain",
            ], falsePositiveNotes: "Developer hosts may co-locate dual-use paths; rank production remote hosts first."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 27, esfExpected: ["OPEN", "EXEC", "READ"]))]
    }
}
