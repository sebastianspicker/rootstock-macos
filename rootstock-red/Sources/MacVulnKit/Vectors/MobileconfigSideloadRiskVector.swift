import Foundation
import RootstockCore

/// Path-to-impact: user-writable mobileconfig / configuration profile sideload risk.
///
/// Research basis: MDM profile delivery tradecraft; user-download profile install research.
/// Safety and behavior: typed ConfigProfileSideloadState × unmanaged MDM compound; never installs profiles.
public struct MobileconfigSideloadRiskVector: Check {
    public static let id = "rootstock.vector.profile.mobileconfig_sideload"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        guard shouldReport(state) else { return [] }
        return [Self.finding(for: state, evidence: evidence(for: state))]
    }

    private func shouldReport(_ state: CollectedState) -> Bool {
        let cfg = state.configProfileSideload
        let userProfiles = cfg?.userMobileconfigPaths.count ?? 0
        let downloads = cfg?.downloadsProfileHints.count ?? 0
        let installDb = cfg?.profileInstallDbPresent
        let note =
            state.collectorNotes["collect.config_profile_sideload"] != nil
            || state.collectorNotes["profile.sideload"] != nil

        let hasUserProfiles = userProfiles > 0 || downloads > 0
        let unmanaged = state.mdm?.enrolled == false || state.mdm?.enrolled == nil
        let weakStore =
            state.mdm?.profileStoreReadable == false
            || (state.mdm?.profileFileCount ?? 0) == 0

        if hasUserProfiles || state.collectorNotes["profile.sideload"] != nil { return true }
        return hasDatabaseRisk(installDb: installDb, unmanaged: unmanaged, weakStore: weakStore, note: note)
    }

    private func hasDatabaseRisk(installDb: Bool?, unmanaged: Bool, weakStore: Bool, note: Bool) -> Bool {
        guard installDb == true || weakStore else { return false }
        return (installDb == true && (unmanaged || weakStore)) || (note && unmanaged)
    }

    private func evidence(for state: CollectedState) -> [Evidence] {
        let cfg = state.configProfileSideload
        let userProfiles = cfg?.userMobileconfigPaths.count ?? 0
        let downloads = cfg?.downloadsProfileHints.count ?? 0
        let installDb = cfg?.profileInstallDbPresent
        let unmanaged = state.mdm?.enrolled == false || state.mdm?.enrolled == nil
        var evidence: [Evidence] = [
            Evidence(
                type: "profile_summary",
                detail:
                    "userMobileconfigs=\(userProfiles) downloadsHints=\(downloads) "
                    + "profileInstallDb=\(installDb.rootstockDescribe) "
                    + "mdmEnrolled=\((state.mdm?.enrolled).rootstockDescribe)"
            ),
        ]
        if let cfg {
            for path in (cfg.userMobileconfigPaths + cfg.downloadsProfileHints).prefix(10) {
                evidence.append(
                    Evidence(type: "mobileconfig_path", path: path, detail: "user-space profile path")
                )
            }
            for n in cfg.notes.prefix(8) {
                evidence.append(Evidence(type: "profile_note", detail: n))
            }
        }
        if unmanaged {
            evidence.append(Evidence(type: "compound_mdm", detail: "host appears unmanaged or enrollment unknown"))
        }
        evidence.append(
            Evidence(
                type: "honesty",
                detail:
                    "Assess lists paths only - never parses payload secrets or installs profiles. "
                    + "User-owned .mobileconfig files are not proof of malicious install."
            )
        )

        return evidence
    }

    private static func finding(for state: CollectedState, evidence: [Evidence]) -> Finding {
        let cfg = state.configProfileSideload
        let userProfiles = cfg?.userMobileconfigPaths.count ?? 0
        let downloads = cfg?.downloadsProfileHints.count ?? 0
        let hasUserProfiles = userProfiles > 0 || downloads > 0
        let unmanaged = state.mdm?.enrolled == false || state.mdm?.enrolled == nil
        let severity: Severity = (hasUserProfiles && unmanaged) ? .medium : .low

        return Finding(id: Self.id, title: hasUserProfiles && unmanaged
                    ? "User-space mobileconfig present on unmanaged (or enrollment-unknown) host"
                    : "Configuration profile / mobileconfig sideload surface", severity: severity, category: .mdm, resolution: .init(evidence: evidence, attackTechniques: ["T1566.001", "T1556", "T1195"], remediation: [
                    "Block unsolicited configuration profile installs via MDM / user education",
                    "Remove leftover .mobileconfig files from Downloads/Desktop on managed fleets",
                    "Require supervised enrollment before accepting high-privilege PPPC payloads",
                    "OPSEC: Rootstock Red never installs system configuration profiles",
                ], falsePositiveNotes: "IT may leave legitimate profiles in Downloads; confirm before incident response."), runtime: .init(confidence: .low, dryRunSafe: true, opsecScore: 16, esfExpected: ["OPEN", "WRITE"]))
    }

}
