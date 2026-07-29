import Foundation
import RootstockCore

/// Path-to-impact: Reminders cloud path residual plane.
public struct RemindersCloudPathVector: Check {
    public static let id = "rootstock.vector.data.reminders_cloud_path"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.remindersCloudPath
        let a = s?.remindersAppPaths.count ?? 0
        let b = s?.remindersStorePaths.count ?? 0
        let c = s?.remindersPrefPaths.count ?? 0
        let surface = s?.remindersCloudSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.reminders_cloud_path"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        var evidence: [Evidence] = [
            Evidence(type: "reminders_cloud_path_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(compound.remote) fda=\(compound.fullDiskAccess)"),
        ]
        if let s {
            evidence += VectorEvidence.paths(s.remindersAppPaths + s.remindersStorePaths + s.remindersPrefPaths, type: "reminders_cloud_path_path", detail: "Reminders cloud path path", limit: 10)
            evidence += VectorEvidence.notes(s.notes, type: "reminders_cloud_path_note", limit: 4)
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never reads reminder titles/bodies or exports Reminders databases."))
        let severity = compound.surfaceSeverity(pathPairCount: a + b)
        return [Finding(id: Self.id, title: compound.remote ? "Reminders cloud path with remote amplifier" : "Reminders cloud path residual plane", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1005", "T1213", "T1083"], remediation: [
                "Inventory and baseline Reminders cloud path paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never reads reminder titles/bodies or exports Reminders databases",
            ], falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]))]
    }
}
