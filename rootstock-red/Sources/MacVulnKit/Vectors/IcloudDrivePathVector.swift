import Foundation
import RootstockCore

/// Path-to-impact: iCloud Drive / Mobile Documents path plane.
public struct IcloudDrivePathVector: Check {
    public static let id = "rootstock.vector.data.icloud_drive_path"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.icloudDrivePath
        let a = s?.mobileDocumentsPaths.count ?? 0
        let b = s?.icloudDrivePaths.count ?? 0
        let c = s?.cloudKitPaths.count ?? 0
        let surface = s?.icloudPathSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.icloud_drive_path"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        var evidence: [Evidence] = [
            Evidence(type: "icloud_drive_path_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(compound.remote) fda=\(compound.fullDiskAccess)"),
        ]
        if let s {
            evidence += VectorEvidence.paths(s.mobileDocumentsPaths + s.icloudDrivePaths + s.cloudKitPaths, type: "icloud_drive_path_path", detail: "iCloud Drive path plane path", limit: 12)
            evidence += VectorEvidence.notes(s.notes, type: "icloud_drive_path_note", limit: 5)
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never enumerates iCloud file contents or exfiltrates Mobile Documents."))
        let severity = compound.surfaceSeverity(pathPairCount: a + b)
        return [Finding(id: Self.id, title: compound.remote ? "iCloud Drive path plane with remote amplifier" : "iCloud Drive / Mobile Documents path plane", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1530", "T1005", "T1567"], remediation: [
                "Inventory and baseline iCloud Drive path plane paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never enumerates iCloud file contents or exfiltrates Mobile Documents",
            ], falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]))]
    }
}
