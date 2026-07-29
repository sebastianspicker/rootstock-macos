import Foundation
import RootstockCore

/// Path-to-impact: multi-app info-stealer collection path plane (beyond browser session alone).
///
/// Research basis: AMOS/Atomic/Odyssey/PXA 2025–2026 infostealer collection themes.
/// Safety and behavior: multi-app path compounds with FDA/remote; never dumps secrets.
public struct InfoStealerPathPlaneVector: Check {
    public static let id = "rootstock.vector.data.infostealer_path_plane"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        guard hasSurface(state), hasInventory(state) else { return [] }
        return [Self.finding(for: state, evidence: evidence(for: state))]
    }

    private func hasSurface(_ state: CollectedState) -> Bool {
        let sp = state.infoStealerPathPlane
        let browser = sp?.browserAdjacentPaths.count ?? 0
        let messaging = sp?.messagingAndVaultPaths.count ?? 0
        let wallet = sp?.walletAndSyncPaths.count ?? 0
        let total = browser + messaging + wallet
        let surface = sp?.collectionSurfacePresent == true || total >= 4
        let note = state.collectorNotes["collect.infostealer_path_plane"] != nil
        return surface || note
    }

    private func hasInventory(_ state: CollectedState) -> Bool {
        let sp = state.infoStealerPathPlane
        let browser = sp?.browserAdjacentPaths.count ?? 0
        let messaging = sp?.messagingAndVaultPaths.count ?? 0
        let wallet = sp?.walletAndSyncPaths.count ?? 0
        let total = browser + messaging + wallet
        return total >= 3 || (browser >= 1 && messaging >= 1)
    }

    private func evidence(for state: CollectedState) -> [Evidence] {
        let sp = state.infoStealerPathPlane
        let browser = sp?.browserAdjacentPaths.count ?? 0
        let messaging = sp?.messagingAndVaultPaths.count ?? 0
        let wallet = sp?.walletAndSyncPaths.count ?? 0
        let fda = state.tcc?.fullDiskAccessLikely == true
        let remote =
            state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true
        let sensorThin =
            state.esf?.clientPaths.isEmpty == true
            || state.securityProducts.filter(\.present).isEmpty

        var evidence: [Evidence] = [
            Evidence(
                type: "stealer_path_summary",
                detail:
                    "browser=\(browser) messagingVault=\(messaging) walletSync=\(wallet) "
                    + "fda=\(fda) remote=\(remote) sensorThin=\(sensorThin)"
            ),
        ]
        if let sp {
            for path in (sp.browserAdjacentPaths + sp.messagingAndVaultPaths + sp.walletAndSyncPaths).prefix(14) {
                evidence.append(Evidence(type: "collection_path", path: path, detail: "stealer-class path (meta only)"))
            }
            for n in sp.notes.prefix(6) {
                evidence.append(Evidence(type: "collection_note", detail: n))
            }
        }
        evidence.append(
            Evidence(
                type: "honesty",
                detail:
                    "Assess never dumps cookies, passwords, keychain items, Messages/Mail contents, "
                    + "or crypto wallet material. Path inventory and compounds only."
            )
        )

        return evidence
    }

    private static func finding(for state: CollectedState, evidence: [Evidence]) -> Finding {
        let sp = state.infoStealerPathPlane
        let browser = sp?.browserAdjacentPaths.count ?? 0
        let messaging = sp?.messagingAndVaultPaths.count ?? 0
        let wallet = sp?.walletAndSyncPaths.count ?? 0
        let total = browser + messaging + wallet
        let fda = state.tcc?.fullDiskAccessLikely == true
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let sensorThin = state.esf?.clientPaths.isEmpty == true
            || state.securityProducts.filter(\.present).isEmpty
        let severity: Severity
        if fda && total >= 6 && (remote || sensorThin) {
            severity = .high
        } else if fda || total >= 8 || (messaging >= 3 && browser >= 1) {
            severity = .medium
        } else {
            severity = .low
        }

        return Finding(id: Self.id, title: fda
                    ? "Info-stealer multi-app collection paths under likely Full Disk Access"
                    : "Info-stealer multi-app collection path plane", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1555", "T1005", "T1539"], remediation: [
                    "Limit Full Disk Access grants to approved security/backup agents only",
                    "Monitor multi-app data-store access patterns (browser + Mail/Messages + vault apps)",
                    "Prefer platform keychain/secure enclave patterns; educate users on stealer paste-run delivery",
                    "OPSEC: Rootstock Red does not harvest cookies, passwords, or wallet keys",
                ], falsePositiveNotes: "Browser, Mail, and Documents paths exist on typical Macs. Prioritize FDA + remote "
                    + "+ multi-family path co-presence for stealer-class engagement narrative."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ"]))
    }
}
