import Foundation
import RootstockCore

/// Path-to-impact: Calendar server / CalDAV residual surface.
public struct CalendarServerPathVector: Check {
    public static let id = "rootstock.vector.data.calendar_server_path"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.calendarServerPath
        let a = s?.caldavFrameworkPaths.count ?? 0
        let b = s?.calendarsStorePaths.count ?? 0
        let c = s?.calendarAgentPaths.count ?? 0
        let surface = s?.caldavSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.calendar_server_path"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        var evidence: [Evidence] = [
            Evidence(type: "calendar_server_path_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(compound.remote) fda=\(compound.fullDiskAccess)"),
        ]
        if let s {
            evidence += VectorEvidence.paths(s.caldavFrameworkPaths + s.calendarsStorePaths + s.calendarAgentPaths, type: "calendar_server_path_path", detail: "Calendar CalDAV residual path", limit: 10)
            evidence += VectorEvidence.notes(s.notes, type: "calendar_server_path_note", limit: 4)
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never reads calendar event bodies or credentials from CalDAV stores."))
        let severity = compound.surfaceSeverity(pathPairCount: a + b)
        return [Finding(id: Self.id, title: compound.remote ? "Calendar CalDAV residual with remote amplifier" : "Calendar server / CalDAV residual surface", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1213", "T1005", "T1071"], remediation: [
                "Inventory and baseline Calendar CalDAV residual paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never reads calendar event bodies or credentials from CalDAV stores",
            ], falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]))]
    }
}
