import Foundation
import RootstockCore

/// Path-to-impact: Continuity / AirDrop proximity transfer surface.
///
/// Research basis: AirDrop preference checklists; proximity data-transfer research.
/// Safety and behavior: typed compound with FDA/session paths; never scrapes pasteboard or forces sends.
public struct ContinuityAirDropSurfaceVector: Check {
    public static let id = "rootstock.vector.continuity.airdrop_surface"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        guard shouldReport(state) else { return [] }
        return [Self.finding(for: state, evidence: evidence(for: state))]
    }

    private func shouldReport(_ state: CollectedState) -> Bool {
        hasSurface(state) && hasImpact(state)
    }

    private func hasSurface(_ state: CollectedState) -> Bool {
        let cont = state.continuityAirDrop
        let airdrop = cont?.airdropPrefPaths.count ?? 0
        let continuity = cont?.continuityFrameworkPaths.count ?? 0
        let nearby = cont?.nearbyShareHints.count ?? 0
        return cont?.proximitySurfacePresent == true || airdrop + continuity + nearby > 0
            || state.collectorNotes["collect.continuity_airdrop"] != nil
    }

    private func hasImpact(_ state: CollectedState) -> Bool {
        let cont = state.continuityAirDrop
        let airdrop = cont?.airdropPrefPaths.count ?? 0
        let continuity = cont?.continuityFrameworkPaths.count ?? 0
        let fda = state.tcc?.fullDiskAccessLikely == true
        let sensitive = state.browserMeta.contains(where: \.exists) || state.credPaths.contains(where: \.exists)
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let axSignals = state.tcc?.domainSignals.contains { $0.lowercased().contains("screen") || $0.lowercased().contains("accessib") } ?? false
        return fda || sensitive || remote || axSignals || airdrop + continuity >= 2
    }

    private func evidence(for state: CollectedState) -> [Evidence] {
        let cont = state.continuityAirDrop
        let airdrop = cont?.airdropPrefPaths.count ?? 0
        let continuity = cont?.continuityFrameworkPaths.count ?? 0
        let nearby = cont?.nearbyShareHints.count ?? 0
        let fda = state.tcc?.fullDiskAccessLikely == true
        let sensitive = state.browserMeta.contains(where: \.exists) || state.credPaths.contains(where: \.exists)
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        var evidence: [Evidence] = [
            Evidence(
                type: "continuity_summary",
                detail:
                    "airdropPrefs=\(airdrop) continuity=\(continuity) nearby=\(nearby) "
                    + "fda=\(fda) sensitivePaths=\(sensitive) remote=\(remote)"
            ),
        ]
        if let cont {
            for path in (cont.airdropPrefPaths + cont.continuityFrameworkPaths + cont.nearbyShareHints)
                .prefix(12)
            {
                evidence.append(Evidence(type: "continuity_path", path: path, detail: "proximity component"))
            }
            for n in cont.notes.prefix(6) {
                evidence.append(Evidence(type: "continuity_note", detail: n))
            }
        }
        evidence.append(
            Evidence(
                type: "honesty",
                detail:
                    "Assess never reads Universal Clipboard contents, never forces AirDrop transfers, "
                    + "never builds proximity malware."
            )
        )
        return evidence
    }

    private static func finding(for state: CollectedState, evidence: [Evidence]) -> Finding {
        let fda = state.tcc?.fullDiskAccessLikely == true
        let sensitive = state.browserMeta.contains(where: \.exists) || state.credPaths.contains(where: \.exists)
        let severity: Severity = (fda && sensitive) ? .medium : .low
        return Finding(id: Self.id, title: sensitive
                    ? "Continuity/AirDrop proximity surface near sensitive session path inventory"
                    : "Continuity / AirDrop proximity transfer surface", severity: severity, category: .network, resolution: .init(evidence: evidence, attackTechniques: ["T1091", "T1005", "T1011"], remediation: [
                    "Restrict AirDrop to contacts-only or off on high-value endpoints via MDM",
                    "Disable Continuity features where policy forbids multi-device handoff",
                    "Physically secure endpoints with open proximity transfer",
                    "OPSEC: Rootstock Red does not exfil pasteboard or weaponize AirDrop",
                ], falsePositiveNotes: "Continuity frameworks are stock on modern macOS. Prioritize open-receive policy "
                    + "compounds with high-value data paths when policy signals exist."), runtime: .init(confidence: .low, dryRunSafe: true, opsecScore: 15, tccDomains: fda ? ["FullDiskAccess"] : [], esfExpected: ["OPEN"]))
    }
}
