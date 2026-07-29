import Foundation
import RootstockCore

/// Wave-12 compound: Network share mount × remote/FDA path-to-impact.
public struct NetworkShareRemoteCompoundVector: Check {
    public static let id = "rootstock.vector.network.share_remote_compound"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.networkShareMount
        let a = s?.smbClientPaths.count ?? 0
        let b = s?.netAuthPaths.count ?? 0
        guard a >= 1, b >= 1 || a >= 2 else { return [] }

        let remote =
            state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true
        let sensorThin =
            state.esf?.clientPaths.isEmpty == true
            || state.securityProducts.filter(\.present).isEmpty
        guard remote || fda || sensorThin || a + b >= 3 else { return [] }

        var evidence: [Evidence] = [
            Evidence(
                type: "network_share_compound",
                detail: "a=\(a) b=\(b) remote=\(remote) fda=\(fda) sensorThin=\(sensorThin)"
            ),
        ]
        if let s {
            for path in (s.smbClientPaths + s.netAuthPaths).prefix(8) {
                evidence.append(Evidence(type: "compound_path", path: path, detail: "Network share mount compound"))
            }
        }
        evidence.append(Evidence(type: "honesty", detail: "never mounts attacker shares or writes credentials to NetAuth."))

        let severity: Severity
        if remote && fda {
            severity = .high
        } else if remote || fda || sensorThin {
            severity = .medium
        } else {
            severity = .low
        }

        return [
            Finding(id: Self.id, title: remote
                    ? "Network share mount × remote compound"
                    : "Network share mount × impact compound", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1021.002", "T1135", "T1080"], remediation: [
                    "Prioritize hosts co-locating Network share mount with remote/FDA amplifiers",
                    "Use Wave-12 lab plans under ROE for purple validation",
                    "OPSEC: path-to-impact ranking only - not an auto-exploit chain",
                ], falsePositiveNotes: "Developer hosts may co-locate many dual-use paths; rank production remote hosts first."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 27, esfExpected: ["OPEN", "EXEC", "READ"])),
        ]
    }
}
