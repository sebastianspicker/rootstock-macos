import Foundation
import RootstockCore

/// Path-to-impact: Notification Center residual depth.
public struct NotificationCenterDepthVector: Check {
    public static let id = "rootstock.vector.data.notification_center_depth"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.notificationCenterDepth
        let a = s?.notificationFrameworkPaths.count ?? 0
        let b = s?.notificationStorePaths.count ?? 0
        let c = s?.notificationPrefPaths.count ?? 0
        let surface = s?.notificationSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.notification_center_depth"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        var evidence: [Evidence] = [
            Evidence(type: "notification_center_depth_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(compound.remote) fda=\(compound.fullDiskAccess)"),
        ]
        if let s {
            evidence += VectorEvidence.paths(s.notificationFrameworkPaths + s.notificationStorePaths + s.notificationPrefPaths, type: "notification_center_depth_path", detail: "Notification Center depth path", limit: 10)
            evidence += VectorEvidence.notes(s.notes, type: "notification_center_depth_note", limit: 4)
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never dumps notification body contents or forges notification payloads."))
        let severity = compound.surfaceSeverity(pathPairCount: a + b)
        return [Finding(id: Self.id, title: compound.remote ? "Notification Center depth with remote amplifier" : "Notification Center residual depth", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1518", "T1083", "T1005"], remediation: [
                "Inventory and baseline Notification Center depth paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never dumps notification body contents or forges notification payloads",
            ], falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]))]
    }
}
