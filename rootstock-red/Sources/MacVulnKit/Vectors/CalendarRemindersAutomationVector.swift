import Foundation
import RootstockCore

/// Path-to-impact: Calendar / Reminders automation lateral surface.
public struct CalendarRemindersAutomationVector: Check {
    public static let id = "rootstock.vector.automation.calendar_reminders"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.calendarRemindersAutomation
        let a = s?.calendarAppPaths.count ?? 0
        let b = s?.remindersPaths.count ?? 0
        let c = s?.eventKitPaths.count ?? 0
        let surface = s?.automationSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.calendar_reminders_automation"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        var evidence: [Evidence] = [
            Evidence(type: "calendar_reminders_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(compound.remote) fda=\(compound.fullDiskAccess)"),
        ]
        if let s {
            evidence += VectorEvidence.paths(s.calendarAppPaths + s.remindersPaths + s.eventKitPaths, type: "calendar_reminders_path", detail: "Calendar/Reminders automation path", limit: 12)
            evidence += VectorEvidence.notes(s.notes, type: "calendar_reminders_note", limit: 6)
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never reads event contents or creates malicious calendar invites."))
        let severity = compound.surfaceSeverity(pathPairCount: a + b)
        return [Finding(id: Self.id, title: compound.remote ? "Calendar/Reminders automation with remote access amplifier" : "Calendar / Reminders automation lateral surface", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1059", "T1546", "T1115"], remediation: [
                "Inventory and baseline Calendar/Reminders automation paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never reads event contents or creates malicious calendar invites",
            ], falsePositiveNotes: "Stock macOS paths often exist. Elevate multi-path co-presence with remote/FDA."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]))]
    }
}
