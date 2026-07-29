import Foundation
import RootstockCore

/// Wave-10 compound depth: multi-app stealer paths × remote access or FDA.
///
/// Research basis: AMOS/Atomic/Odyssey/PXA 2025–2026 infostealer collection themes.
/// Safety and behavior: multi-app path plane compounded with SSH/ARD or FDA; never dumps secrets.
public struct StealerRemoteCompoundVector: Check {
    private struct PathCounts {
        let browser: Int
        let messaging: Int
        let wallet: Int
    }
    public static let id = "rootstock.vector.data.stealer_remote_compound"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        guard Self.hasStealerSurface(state), Self.hasAmplifier(state) else { return [] }
        return [Self.finding(for: state, evidence: evidence(for: state))]
    }


    private static func counts(_ state: CollectedState) -> PathCounts {
        let plane = state.infoStealerPathPlane
        return PathCounts(
            browser: plane?.browserAdjacentPaths.count ?? 0,
            messaging: plane?.messagingAndVaultPaths.count ?? 0,
            wallet: plane?.walletAndSyncPaths.count ?? 0
        )
    }

    private static func hasStealerSurface(_ state: CollectedState) -> Bool {
        let counts = counts(state)
        return counts.browser + counts.messaging + counts.wallet >= 3
            || (counts.browser >= 1 && counts.messaging >= 1)
    }

    private static func hasAmplifier(_ state: CollectedState) -> Bool {
        remoteAccess(state) || state.tcc?.fullDiskAccessLikely == true
    }

    private static func remoteAccess(_ state: CollectedState) -> Bool {
        state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
    }

    private func evidence(for state: CollectedState) -> [Evidence] {
        let counts = Self.counts(state), total = counts.browser + counts.messaging + counts.wallet
        let remote = Self.remoteAccess(state), fda = state.tcc?.fullDiskAccessLikely == true
        let sensorThin = state.esf?.clientPaths.isEmpty == true || state.securityProducts.filter(\.present).isEmpty
        var evidence: [Evidence] = [Evidence(type: "stealer_remote_compound_summary", detail: "browser=\(counts.browser) messagingVault=\(counts.messaging) walletSync=\(counts.wallet) total=\(total) " + "remote=\(remote) fda=\(fda) sensorThin=\(sensorThin)")]
        if let plane = state.infoStealerPathPlane {
            for path in (plane.browserAdjacentPaths + plane.messagingAndVaultPaths + plane.walletAndSyncPaths).prefix(12) { evidence.append(Evidence(type: "collection_path", path: path, detail: "stealer-class path (meta only)")) }
            for note in plane.notes.prefix(4) { evidence.append(Evidence(type: "collection_note", detail: note)) }
        }
        evidence.append(Evidence(type: "compound_amplifier", detail: "impact amplifiers: remote=\(remote) fda=\(fda) " + "(path-to-impact ranking - no secret harvest)"))
        evidence.append(Evidence(type: "honesty", detail: "Assess never dumps cookies, passwords, keychain items, Messages/Mail contents, " + "or crypto wallet material. Multi-app path compounds only."))
        return evidence
    }

    private static func finding(for state: CollectedState, evidence: [Evidence]) -> Finding {
        let counts = counts(state), total = counts.browser + counts.messaging + counts.wallet
        let remote = remoteAccess(state), fda = state.tcc?.fullDiskAccessLikely == true
        let severity: Severity = fda && remote && total >= 6 ? .high : ((fda && total >= 4) || (remote && counts.browser >= 1 && counts.messaging >= 1) ? .medium : .low)
        let title = remote && fda ? "Info-stealer multi-app paths compound with remote access and FDA" : (fda ? "Info-stealer multi-app paths under likely Full Disk Access" : "Info-stealer multi-app paths compound with remote access")
        return Finding(id: Self.id, title: title, severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1555", "T1005", "T1539", "T1021.004"], remediation: ["Limit Full Disk Access grants to approved security/backup agents only", "Disable unnecessary Remote Login / Screen Sharing on high-value collection hosts", "Monitor multi-app data-store access patterns (browser + Mail/Messages + vault apps)", "OPSEC: Rootstock Red does not harvest cookies, passwords, or wallet keys"], falsePositiveNotes: "Browser and Documents paths exist on typical Macs. Prioritize multi-family path " + "co-presence with FDA or remote access for stealer-class engagement narrative."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 26, esfExpected: ["OPEN", "READ"]))
    }
}
