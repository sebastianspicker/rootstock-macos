import Foundation
import RootstockCore

/// Path-to-impact: Shortcuts iCloud sync residual depth.
public struct ShortcutsIcloudSyncVector: Check {
    public static let id = "rootstock.vector.automation.shortcuts_icloud_sync"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.shortcutsIcloudSync
        let a = s?.shortcutsAppPaths.count ?? 0
        let b = s?.shortcutsDbPaths.count ?? 0
        let c = s?.shortcutsPrefPaths.count ?? 0
        let surface = s?.shortcutsIcloudSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.shortcuts_icloud_sync"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        var evidence: [Evidence] = [
            Evidence(type: "shortcuts_icloud_sync_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(compound.remote) fda=\(compound.fullDiskAccess)"),
        ]
        if let s {
            evidence += VectorEvidence.paths(s.shortcutsAppPaths + s.shortcutsDbPaths + s.shortcutsPrefPaths, type: "shortcuts_icloud_sync_path", detail: "Shortcuts iCloud sync path", limit: 10)
            evidence += VectorEvidence.notes(s.notes, type: "shortcuts_icloud_sync_note", limit: 4)
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never executes Shortcuts or dumps iCloud-synced automation databases."))
        let severity = compound.surfaceSeverity(pathPairCount: a + b)
        return [Finding(id: Self.id, title: compound.remote ? "Shortcuts iCloud sync with remote amplifier" : "Shortcuts iCloud sync residual depth", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1059", "T1530", "T1083"], remediation: [
                "Inventory and baseline Shortcuts iCloud sync paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never executes Shortcuts or dumps iCloud-synced automation databases",
            ], falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]))]
    }
}
