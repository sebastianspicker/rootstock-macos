import Foundation
import RootstockCore

/// Lateral / remote access vector from SSH / Screen Sharing posture (path + enable heuristics).
public struct RemoteAccessSurfaceVector: Check {
    public static let id = "rootstock.vector.network.remote_access_surface"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        guard Self.hasRemoteAccessSurface(state) else { return [] }
        return [Self.finding(for: state, evidence: evidence(for: state))]
    }


    private static func hasRemoteAccessSurface(_ state: CollectedState) -> Bool {
        guard let net = state.network else { return false }
        return net.remoteLoginSSH == true || net.screenSharingARD == true
            || net.remoteLoginPlistPresent == true || net.screenSharingPlistPresent == true
            || net.sshdConfigPresent == true || net.remoteManagementPrefsPresent == true
    }

    private func evidence(for state: CollectedState) -> [Evidence] {
        guard let net = state.network else { return [] }
        var evidence = net.notes.prefix(15).map { Evidence(type: "note", detail: $0) }
        evidence.append(Evidence(type: "ssh", detail: "remoteLoginSSH=\(net.remoteLoginSSH.rootstockDescribe) " + "plistPresent=\(net.remoteLoginPlistPresent.rootstockDescribe) " + "sshdConfigPresent=\(net.sshdConfigPresent.rootstockDescribe)"))
        evidence.append(Evidence(type: "screen_sharing", detail: "screenSharingARD=\(net.screenSharingARD.rootstockDescribe) " + "plistPresent=\(net.screenSharingPlistPresent.rootstockDescribe) " + "remoteMgmtPrefs=\(net.remoteManagementPrefsPresent.rootstockDescribe)"))
        if Self.hasSMBSurface(net) { evidence.append(Evidence(type: "smb", detail: "fileSharingSMB=\(net.fileSharingSMB.rootstockDescribe) " + "plistPresent=\(net.fileSharingPlistPresent.rootstockDescribe)")) }
        return evidence
    }

    private static func hasSMBSurface(_ net: NetworkState) -> Bool {
        net.fileSharingSMB == true || net.fileSharingPlistPresent == true
    }

    private static func finding(for state: CollectedState, evidence: [Evidence]) -> Finding {
        let net = state.network!
        let enabled = enabledServices(net)
        let presentOnly = componentOnlyServices(net)
        let isEnabled = !enabled.isEmpty
        let title = isEnabled ? "Remote access vector: \(enabled.joined(separator: ", ")) indicated enabled" : "Remote access surface present (\(presentOnly.joined(separator: ", "))) - enablement uncertain"
        return Finding(id: Self.id, title: title, severity: isEnabled ? .medium : .low, category: .network, resolution: .init(evidence: evidence, attackTechniques: ["T1021.004", "T1021.001", "T1021.002", "T1133"], remediation: ["Disable unused Remote Login, Screen Sharing, and Remote Management", "Require strong auth (keys/certificates) and network controls if SSH must stay on", "Prefer MDM-enforced sharing posture; segment management networks", "OPSEC: path heuristics are quiet; port scanning would be noisier and is out of scope"], falsePositiveNotes: "LaunchDaemon plists / sshd_config often exist when services are disabled"), runtime: .init(confidence: isEnabled ? .medium : .low, dryRunSafe: true, opsecScore: 16, esfExpected: ["OPEN", "CONNECT"]))
    }

    private static func enabledServices(_ net: NetworkState) -> [String] {
        [net.remoteLoginSSH == true ? "SSH/Remote Login" : nil, net.screenSharingARD == true ? "Screen Sharing/ARD" : nil, net.fileSharingSMB == true ? "SMB File Sharing" : nil].compactMap { $0 }
    }

    private static func componentOnlyServices(_ net: NetworkState) -> [String] {
        [net.remoteLoginSSH != true && (net.remoteLoginPlistPresent == true || net.sshdConfigPresent == true) ? "ssh components" : nil, net.screenSharingARD != true && (net.screenSharingPlistPresent == true || net.remoteManagementPrefsPresent == true) ? "ARD/screen sharing components" : nil].compactMap { $0 }
    }

}
