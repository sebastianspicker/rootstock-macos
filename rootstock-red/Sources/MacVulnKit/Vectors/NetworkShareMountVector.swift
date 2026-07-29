import Foundation
import RootstockCore

/// Path-to-impact: Network share / SMB mount dual-use lateral.
///
/// Research basis: Network share mount 2025–26 themes.
/// Safety and behavior: path compounds with remote/FDA amplifiers; never mounts attacker shares or writes credentials to NetAuth.
public struct NetworkShareMountVector: Check {
    public static let id = "rootstock.vector.network.share_mount_surface"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.networkShareMount
        let a = s?.smbClientPaths.count ?? 0
        let b = s?.netAuthPaths.count ?? 0
        let c = s?.mountPointHints.count ?? 0
        let surface = s?.shareSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.network_share_mount"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }

        let remote =
            state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true

        var evidence: [Evidence] = [
            Evidence(
                type: "network_share_summary",
                detail: "a=\(a) b=\(b) c=\(c) remote=\(remote) fda=\(fda)"
            ),
        ]
        if let s {
            for path in (s.smbClientPaths + s.netAuthPaths + s.mountPointHints).prefix(12) {
                evidence.append(Evidence(type: "network_share_path", path: path, detail: "Network share mount path"))
            }
            for n in s.notes.prefix(6) {
                evidence.append(Evidence(type: "network_share_note", detail: n))
            }
        }
        evidence.append(
            Evidence(
                type: "honesty",
                detail: "Assess never mounts attacker shares or writes credentials to NetAuth."
            )
        )

        let severity: Severity
        if remote && fda && a + b >= 3 {
            severity = .high
        } else if remote || fda || a + b >= 2 {
            severity = .medium
        } else {
            severity = .low
        }

        return [
            Finding(id: Self.id, title: remote
                    ? "Network share mount with remote access amplifier"
                    : "Network share / SMB mount dual-use lateral", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1021.002", "T1135", "T1080"], remediation: [
                    "Inventory and baseline Network share mount paths via MDM/EDR",
                    "Correlate unexpected path co-presence with delivery timelines",
                    "Prioritize hosts with remote/FDA amplifiers",
                    "OPSEC: Rootstock Red never mounts attacker shares or writes credentials to NetAuth",
                ], falsePositiveNotes: "Stock macOS paths often exist. Elevate multi-path co-presence with remote/FDA amplifiers."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"])),
        ]
    }
}
