import Foundation
import RootstockCore

/// Path-to-impact: Time Machine / local snapshot as alternate data-access surface.
///
/// Research basis: backup/snapshot data-access research; PEASS filesystem themes.
/// Safety and behavior: typed TimeMachineState × FDA/cred compound; never dumps backup contents.
public struct TimeMachineSnapshotAccessVector: Check {
    public static let id = "rootstock.vector.tm.snapshot_data_access"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        guard Self.hasTimeMachineSurface(state) else { return [] }
        return [Self.finding(for: state, evidence: evidence(for: state))]
    }


    private static func hasTimeMachineSurface(_ state: CollectedState) -> Bool {
        let tm = state.timeMachine
        return tm?.preferencesPresent == true || (tm?.backupPaths.count ?? 0) > 0
            || (tm?.localSnapshotHints.count ?? 0) > 0 || (tm?.volumeMountHints.count ?? 0) > 0
            || state.collectorNotes["collect.time_machine"] != nil || state.collectorNotes["tm.snapshot_surface"] != nil
    }

    private static func sensitivePaths(_ state: CollectedState) -> Bool {
        state.credPaths.contains(where: \.exists) || state.browserMeta.contains(where: \.exists)
    }

    private func evidence(for state: CollectedState) -> [Evidence] {
        let tm = state.timeMachine, backups = tm?.backupPaths.count ?? 0, snapshots = tm?.localSnapshotHints.count ?? 0, volumes = tm?.volumeMountHints.count ?? 0
        let fda = state.tcc?.fullDiskAccessLikely == true, sensitive = Self.sensitivePaths(state)
        var evidence: [Evidence] = [Evidence(type: "tm_summary", detail: "preferencesPresent=\((tm?.preferencesPresent).rootstockDescribe) " + "backupPaths=\(backups) localSnapshots=\(snapshots) volumeHints=\(volumes)")]
        if let tm {
            for path in (tm.backupPaths + tm.localSnapshotHints + tm.volumeMountHints).prefix(10) { evidence.append(Evidence(type: "tm_path", path: path, detail: "TM/snapshot path hint")) }
            for note in tm.notes.prefix(8) { evidence.append(Evidence(type: "tm_note", detail: note)) }
        }
        if fda { evidence.append(Evidence(type: "compound_fda", detail: "fullDiskAccessLikely=true")) }
        if sensitive { evidence.append(Evidence(type: "compound_sensitive", detail: "credPaths=\(state.credPaths.filter(\.exists).count) " + "browserMetaExists=\(state.browserMeta.filter(\.exists).count)")) }
        evidence.append(Evidence(type: "honesty", detail: "Assess never reads backup payloads, keychains inside snapshots, or browser DBs. " + "Local snapshots may retain deleted material - treat as data-access surface."))
        return evidence
    }

    private static func finding(for state: CollectedState, evidence: [Evidence]) -> Finding {
        let tm = state.timeMachine, backups = tm?.backupPaths.count ?? 0, snapshots = tm?.localSnapshotHints.count ?? 0, fda = state.tcc?.fullDiskAccessLikely == true
        return Finding(id: Self.id, title: fda ? "Time Machine / snapshot data-access surface with FDA-likely posture" : "Time Machine / local snapshot data-access surface", severity: fda && (backups > 0 || snapshots > 0) ? .medium : .low, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1005", "T1530", "T1083"], remediation: ["Encrypt Time Machine destinations; restrict who has FDA on backup-capable hosts", "Review local snapshot retention on high-value endpoints", "Ensure backup volumes are not world-readable when mounted", "OPSEC: Rootstock Red never restores or dumps TM contents"], falsePositiveNotes: "TM prefs present on many Macs; prioritize FDA + mounted backup compounds."), runtime: .init(confidence: .low, dryRunSafe: true, opsecScore: 20, tccDomains: fda ? ["FullDiskAccess"] : [], esfExpected: ["OPEN"]))
    }

}
