import Foundation
import RootstockCore

/// Local sharing / remote access posture (if network state collected).
public struct NetworkSharingPostureCheck: Check {
    public static let id = "rootstock.check.network.sharing_posture"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        guard let net = state.network else { return [] }

        var evidence: [Evidence] = net.notes.prefix(20).map { Evidence(type: "note", detail: $0) }
        evidence.append(
            Evidence(
                type: "ssh",
                detail:
                    "remoteLoginSSH=\(net.remoteLoginSSH.rootstockDescribe) "
                    + "plistPresent=\(net.remoteLoginPlistPresent.rootstockDescribe) "
                    + "sshdConfigPresent=\(net.sshdConfigPresent.rootstockDescribe)"
            )
        )
        evidence.append(
            Evidence(
                type: "ard",
                detail:
                    "screenSharingARD=\(net.screenSharingARD.rootstockDescribe) "
                    + "plistPresent=\(net.screenSharingPlistPresent.rootstockDescribe) "
                    + "remoteMgmtPrefs=\(net.remoteManagementPrefsPresent.rootstockDescribe)"
            )
        )
        evidence.append(
            Evidence(
                type: "smb",
                detail:
                    "fileSharingSMB=\(net.fileSharingSMB.rootstockDescribe) "
                    + "plistPresent=\(net.fileSharingPlistPresent.rootstockDescribe)"
            )
        )

        let enabledServices = [
            ("SSH/Remote Login", net.remoteLoginSSH),
            ("Screen Sharing/ARD", net.screenSharingARD),
            ("SMB File Sharing", net.fileSharingSMB),
        ].filter { $0.1 == true }.map(\.0)

        let severity: Severity
        let title: String
        if !enabledServices.isEmpty {
            severity = .medium
            title = "Sharing services indicated enabled: \(enabledServices.joined(separator: ", "))"
        } else {
            severity = .info
            title = "Network sharing posture (partial heuristics)"
        }

        return [
            Finding(id: Self.id, title: title, severity: severity, category: .network, resolution: .init(evidence: evidence, attackTechniques: ["T1021.002", "T1021.004", "T1021.001"], remediation: [
                    "Disable unused Remote Login, Screen Sharing, and File Sharing",
                    "Prefer MDM-enforced sharing posture and network segmentation",
                    "System LaunchDaemon plists often exist even when services are disabled",
                ], falsePositiveNotes: "Component/plist presence is not the same as service enabled/listening"), runtime: .init(confidence: enabledServices.isEmpty ? .low : .medium, dryRunSafe: true, opsecScore: 8, esfExpected: [])),
        ]
    }

}
