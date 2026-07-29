import Foundation
import RootstockCore

/// Path-to-impact: Spotlight / mdworker / on-device AI-cache data-access class.
///
/// Research basis: Sploitlight-class Spotlight research; on-device AI cache path awareness.
/// Safety and behavior: path presence + FDA compound; never dumps index or model contents.
public struct SpotlightAICacheAccessVector: Check {
    public static let id = "rootstock.vector.data.spotlight_ai_cache_access"
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
        let sp = state.spotlightAICache
        let spotlight = sp?.spotlightPaths.count ?? 0
        let metadata = sp?.metadataFrameworkPaths.count ?? 0
        let aiCache = sp?.aiCachePathHints.count ?? 0
        let surface = sp?.dataAccessSurfacePresent == true || spotlight + metadata + aiCache > 0
        let note = state.collectorNotes["collect.spotlight_ai_cache"] != nil

        return surface || note
    }

    private func hasImpact(_ state: CollectedState) -> Bool {
        let sp = state.spotlightAICache
        let spotlight = sp?.spotlightPaths.count ?? 0
        let metadata = sp?.metadataFrameworkPaths.count ?? 0
        let fda = state.tcc?.fullDiskAccessLikely == true
        let sensitive = state.browserMeta.contains(where: \.exists) || state.credPaths.contains(where: \.exists)
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        return fda || sensitive || remote || spotlight + metadata >= 3
    }

    private func evidence(for state: CollectedState) -> [Evidence] {
        let sp = state.spotlightAICache
        let spotlight = sp?.spotlightPaths.count ?? 0
        let metadata = sp?.metadataFrameworkPaths.count ?? 0
        let aiCache = sp?.aiCachePathHints.count ?? 0
        let fda = state.tcc?.fullDiskAccessLikely == true
        let sensitive = state.browserMeta.contains(where: \.exists) || state.credPaths.contains(where: \.exists)
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        var evidence: [Evidence] = [
            Evidence(
                type: "spotlight_summary",
                detail:
                    "spotlight=\(spotlight) metadata=\(metadata) aiCache=\(aiCache) "
                    + "fda=\(fda) sensitive=\(sensitive) remote=\(remote)"
            ),
        ]
        if let sp {
            for path in (sp.spotlightPaths + sp.metadataFrameworkPaths + sp.aiCachePathHints).prefix(12) {
                evidence.append(Evidence(type: "index_path", path: path, detail: "index/cache path presence"))
            }
            for n in sp.notes.prefix(6) {
                evidence.append(Evidence(type: "spotlight_note", detail: n))
            }
        }
        evidence.append(
            Evidence(
                type: "honesty",
                detail:
                    "Assess never dumps Spotlight indexes, never extracts AI model or user-cache contents, "
                    + "never weaponizes Sploitlight-class index access."
            )
        )

        return evidence
    }

    private static func finding(for state: CollectedState, evidence: [Evidence]) -> Finding {
        let fda = state.tcc?.fullDiskAccessLikely == true
        let sensitive = state.browserMeta.contains(where: \.exists) || state.credPaths.contains(where: \.exists)
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let severity: Severity = (fda && (sensitive || remote)) ? .medium : .low
        return Finding(id: Self.id, title: fda
                    ? "Spotlight/AI-cache data-access class with Full Disk Access likely"
                    : "Spotlight / mdworker / on-device AI-cache data-access surface", severity: severity, category: .auth, resolution: .init(evidence: evidence, attackTechniques: ["T1005", "T1083", "T1213"], remediation: [
                    "Limit Full Disk Access grants to required security tools only",
                    "Review on-device AI / Intelligence cache policies for high-value hosts",
                    "Monitor mdfind/mdworker abuse patterns via EDR where applicable",
                    "OPSEC: Rootstock Red does not dump indexes or AI cache contents",
                ], falsePositiveNotes: "Spotlight and CoreSpotlight frameworks are stock. Prioritize FDA + sensitive "
                    + "session path compounds for collection-impact narrative."), runtime: .init(confidence: .low, dryRunSafe: true, opsecScore: 20, tccDomains: fda ? ["FullDiskAccess"] : [], esfExpected: ["OPEN"]))
    }
}
