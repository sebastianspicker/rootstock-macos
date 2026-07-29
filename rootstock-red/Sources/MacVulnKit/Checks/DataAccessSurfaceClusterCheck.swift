import Foundation
import RootstockCore

/// Time Machine / mobileconfig / sensitive-path data-access cluster.
///
/// Research basis: backup data-access + profile sideload research.
/// Safety and behavior: multi-rule ranked Findings; never dumps backups or installs profiles.
public struct DataAccessSurfaceClusterCheck: Check {
    public static let id = "rootstock.check.vuln.data_access_surface_cluster"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        var findings: [Finding] = []
        if let f = Self.tmWithFDA(state: state) { findings.append(f) }
        if let f = Self.mobileconfigUnmanaged(state: state) { findings.append(f) }
        if let f = Self.snapshotWithCredPaths(state: state) { findings.append(f) }
        return findings
    }

    private static func tmWithFDA(state: CollectedState) -> Finding? {
        let tm = state.timeMachine
        let surface =
            tm?.preferencesPresent == true
            || !(tm?.backupPaths.isEmpty ?? true)
            || !(tm?.localSnapshotHints.isEmpty ?? true)
            || state.collectorNotes["collect.time_machine"] != nil
            || state.collectorNotes["tm.snapshot_surface"] != nil
        let fda = state.tcc?.fullDiskAccessLikely == true
        guard surface && fda else { return nil }

        return Finding(id: "\(id).tm_with_fda", title: "Data-access cluster: Time Machine / snapshot surface with FDA-likely posture", severity: .medium, category: .misconfig, resolution: .init(evidence: [
                Evidence(
                    type: "tm",
                    detail:
                        "prefs=\((tm?.preferencesPresent).rootstockDescribe) "
                        + "backups=\(tm?.backupPaths.count ?? 0) "
                        + "snapshots=\(tm?.localSnapshotHints.count ?? 0)"
                ),
                Evidence(type: "tcc", detail: "fullDiskAccessLikely=true"),
            ], attackTechniques: ["T1005", "T1530"], remediation: [
                "Encrypt TM destinations; minimize FDA grants on backup-capable hosts",
                "Audit local snapshot retention policy",
            ]), runtime: .init(confidence: .low, dryRunSafe: true, opsecScore: 20, tccDomains: ["FullDiskAccess"], esfExpected: ["OPEN"]))
    }

    private static func mobileconfigUnmanaged(state: CollectedState) -> Finding? {
        let cfg = state.configProfileSideload
        let profiles =
            (cfg?.userMobileconfigPaths.count ?? 0)
            + (cfg?.downloadsProfileHints.count ?? 0)
        let note = state.collectorNotes["profile.sideload"] != nil
            || state.collectorNotes["collect.config_profile_sideload"] != nil
        let unmanaged = state.mdm?.enrolled == false || state.mdm?.enrolled == nil
        guard (profiles > 0 || note) && unmanaged else { return nil }
        // Require either real paths or explicit sideload note
        guard profiles > 0 || state.collectorNotes["profile.sideload"] != nil
            || (cfg?.profileInstallDbPresent == true && unmanaged)
        else { return nil }

        return Finding(id: "\(id).mobileconfig_unmanaged", title: "Data-access cluster: mobileconfig / profile sideload surface on unmanaged host", severity: profiles > 0 ? .medium : .low, category: .mdm, resolution: .init(evidence: [
                Evidence(
                    type: "profile",
                    detail:
                        "userMobileconfigs=\(cfg?.userMobileconfigPaths.count ?? 0) "
                        + "downloads=\(cfg?.downloadsProfileHints.count ?? 0) "
                        + "installDb=\((cfg?.profileInstallDbPresent).rootstockDescribe)"
                ),
                Evidence(type: "mdm", detail: "enrolled=\((state.mdm?.enrolled).rootstockDescribe)"),
            ], attackTechniques: ["T1566.001", "T1556"], remediation: [
                "Enroll hosts; quarantine unexpected .mobileconfig files",
                "User training against unsolicited profile installs",
            ]), runtime: .init(confidence: .low, dryRunSafe: true, opsecScore: 15, esfExpected: ["OPEN", "WRITE"]))
    }

    private static func snapshotWithCredPaths(state: CollectedState) -> Finding? {
        let snaps =
            (state.timeMachine?.localSnapshotHints.count ?? 0)
            + (state.timeMachine?.backupPaths.count ?? 0)
        let creds = state.credPaths.filter(\.exists).count
        guard snaps > 0 && creds > 0 else { return nil }

        return Finding(id: "\(id).snapshot_with_cred_paths", title: "Data-access cluster: snapshot/backup paths compound with credential path inventory", severity: .low, category: .misconfig, resolution: .init(evidence: [
                Evidence(type: "snapshot", detail: "snapshotOrBackupHints=\(snaps)"),
                Evidence(type: "cred_paths", detail: "existingCredPaths=\(creds) (paths only)"),
                Evidence(
                    type: "honesty",
                    detail: "Never reads secret material from backups or credential files"
                ),
            ], attackTechniques: ["T1005", "T1552.001"], remediation: [
                "Ensure backups inherit encryption and access controls of primary volume",
                "Rotate credentials if unauthorized snapshot access is suspected",
            ]), runtime: .init(confidence: .low, dryRunSafe: true, opsecScore: 18, esfExpected: ["OPEN"]))
    }

}
