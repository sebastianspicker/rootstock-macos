import Foundation
import RootstockCore

/// Wave-13 compound: Calendar/Reminders automation × remote/FDA path-to-impact.
public struct CalendarRemoteCompoundVector: Check {
    public static let id = "rootstock.vector.automation.calendar_remote_compound"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.calendarRemindersAutomation
        let a = s?.calendarAppPaths.count ?? 0
        let b = s?.remindersPaths.count ?? 0
        guard a >= 1, b >= 1 || a >= 2 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        guard compound.hasAmplifier || a + b >= 3 else { return [] }
        var evidence: [Evidence] = [
            Evidence(type: "calendar_reminders_compound", detail: "a=\(a) b=\(b) remote=\(compound.remote) fda=\(compound.fullDiskAccess) sensorThin=\(compound.sensorThin)"),
        ]
        if let s {
            for path in (s.calendarAppPaths + s.remindersPaths).prefix(8) {
                evidence.append(Evidence(type: "compound_path", path: path, detail: "Calendar/Reminders automation compound"))
            }
        }
        evidence.append(Evidence(type: "honesty", detail: "never reads event contents or creates malicious calendar invites."))
        let severity = compound.severity
        return [Finding(id: Self.id, title: compound.remote ? "Calendar/Reminders automation × remote compound" : "Calendar/Reminders automation × impact compound", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1059", "T1546", "T1115"], remediation: [
                "Prioritize hosts co-locating Calendar/Reminders automation with remote/FDA amplifiers",
                "Use Wave-13 lab plans under ROE for purple validation",
                "OPSEC: path-to-impact ranking only - not an auto-exploit chain",
            ], falsePositiveNotes: "Developer hosts may co-locate dual-use paths; rank production remote hosts first."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 27, esfExpected: ["OPEN", "EXEC", "READ"]))]
    }
}
