import Foundation
import RootstockCore

/// Multi-plane Wave-9 installer × collection × visibility compound ranking.
///
/// Research basis: engagement narrative across installer design, extractors, stealer paths, visibility, MDM parse.
/// Safety and behavior: deterministic compounds over CollectedState; not automated exploit orchestration.
public struct Wave9InstallerCollectionClusterCheck: Check {
    public static let id = "rootstock.check.vuln.wave9_installer_collection_cluster"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let planes = Self.planeSignals(state: state)
        guard planes.count >= 2 else { return [] }
        return [Self.compoundFinding(planes: planes, state: state)]
    }

    private static func planeSignals(state: CollectedState) -> [String] {
        presentPlaneNames([
            .init(name: "installer_design", isPresent: installerDesignPresent(state)),
            .init(name: "archive_extractor", isPresent: archiveExtractorPresent(state)),
            .init(name: "stealer_paths", isPresent: stealerPathsPresent(state)),
            .init(name: "visibility_depth", isPresent: visibilityDepthPresent(state)),
            .init(name: "profile_parse", isPresent: profileParsePresent(state)),
            .init(name: "remote", isPresent: remoteAccessPresent(state)),
            .init(name: "fda", isPresent: fullDiskAccessPresent(state)),
            .init(name: "sensor_gap", isPresent: sensorGapPresent(state)),
        ])
    }


    private static func installerDesignPresent(_ state: CollectedState) -> Bool {
        let packageKit = state.packageKitInstallerDesign
        return packageKit?.designSurfacePresent == true
            || (packageKit?.installerServicePaths.count ?? 0) > 0
            || (packageKit?.receiptAndHistoryPaths.count ?? 0) >= 1
            || (packageKit?.toolingPaths.count ?? 0) >= 2
    }

    private static func archiveExtractorPresent(_ state: CollectedState) -> Bool {
        let archive = state.archiveQuarantineExtractor
        return archive?.extractorSurfacePresent == true
            || (archive?.thirdPartyExtractorPaths.count ?? 0) > 0
            || (archive?.stockExtractorPaths.count ?? 0) >= 3
    }

    private static func stealerPathsPresent(_ state: CollectedState) -> Bool {
        let stealer = state.infoStealerPathPlane
        let pathCount = (stealer?.browserAdjacentPaths.count ?? 0)
            + (stealer?.messagingAndVaultPaths.count ?? 0)
            + (stealer?.walletAndSyncPaths.count ?? 0)
        return stealer?.collectionSurfacePresent == true || pathCount >= 4
    }

    private static func visibilityDepthPresent(_ state: CollectedState) -> Bool {
        let visibility = state.tccEsfVisibilityDepth
        return visibility?.visibilitySurfacePresent == true
            || (visibility?.tccDbPathHits.count ?? 0) > 0
            || (visibility?.visibilityToolPaths.count ?? 0) > 0
    }

    private static func profileParsePresent(_ state: CollectedState) -> Bool {
        let profile = state.mdmProfileParseDepth
        return (profile?.parsedProfileCount ?? 0) > 0 || (profile?.examinedProfilePaths.count ?? 0) > 0
    }

    private static func remoteAccessPresent(_ state: CollectedState) -> Bool {
        state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
    }

    private static func fullDiskAccessPresent(_ state: CollectedState) -> Bool {
        state.tcc?.fullDiskAccessLikely == true
    }

    private static func sensorGapPresent(_ state: CollectedState) -> Bool {
        state.esf?.clientPaths.isEmpty == true
    }

    private static func compoundFinding(planes: [String], state: CollectedState) -> Finding {
        let sorted = planes.sorted()
        return Finding(id: "\(id).multi_plane", title: title(for: sorted), severity: severity(for: sorted), category: .misconfig, resolution: resolution(for: sorted, state: state), runtime: runtime)
    }

    private static func severity(for planes: [String]) -> Severity {
        if highSeverityPlanes(planes) { return .high }
        return mediumSeverityPlanes(planes) ? .medium : .low
    }

    private static func highSeverityPlanes(_ planes: [String]) -> Bool {
        planes.contains("stealer_paths") && planes.contains("fda") && planes.count >= 4
    }

    private static func mediumSeverityPlanes(_ planes: [String]) -> Bool {
        planes.contains("installer_design") && planes.contains("remote") && planes.count >= 3 || planes.count >= 4
    }

    private static func title(for planes: [String]) -> String {
        let suffix = planes.count > 5 ? ", …" : ""
        return "Wave-9 installer×collection compound: \(planes.count) planes (\(planes.prefix(5).joined(separator: ", "))\(suffix))"
    }

    private static func evidence(for planes: [String], state: CollectedState) -> [Evidence] {
        let stages = stageLabels(for: planes)
        return [Evidence(type: "planes", detail: "planes=\(planes.joined(separator: "|")) count=\(planes.count)"), Evidence(type: "stage_labels", detail: "stages=\(stages.joined(separator: "|")) (labels only - not auto-exploit)"), Evidence(type: "host", detail: "host=\(state.host?.hostname ?? "unknown") user=\(state.host?.username ?? "unknown")"), Evidence(type: "honesty", detail: "Wave-9 compound ranking is path-to-impact narrative for operators. Rootstock Red does not build pkgs, craft Gatekeeper bypass archives, dump stealer secrets, dump TCC.db, or install profiles.")]
    }

    private static func resolution(for planes: [String], state: CollectedState) -> Finding.Resolution {
        .init(evidence: evidence(for: planes, state: state), attackTechniques: ["T1546", "T1553.001", "T1555", "T1562.001"], remediation: ["Prioritize co-occurring installer-design + stealer-paths + FDA/remote planes on tier-0 hosts", "Close remote access and harden package/archive user workflows before lower-tier inventory", "Use Wave-9 lab plans under ROE for purple validation of expected telemetry", "OPSEC: treat multi-plane compounds as engagement narrative, not an exploit script"], falsePositiveNotes: "Developer workstations may legitimately co-locate many Wave-9 planes. Rank production hosts first.")
    }

    private static let runtime = Finding.Runtime(confidence: .low, dryRunSafe: true, opsecScore: 24, esfExpected: ["OPEN", "EXEC", "READ"])

    private static func stageLabels(for planes: [String]) -> [String] {
        let present = Set(planes)
        let definitions = [("delivery_trust", ["archive_extractor"]), ("persistence_design", ["installer_design"]), ("collection_impact", ["stealer_paths", "fda"]), ("detection_gap", ["visibility_depth", "sensor_gap"]), ("config_abuse", ["profile_parse"]), ("lateral_path", ["remote"])]
        let stages = definitions.compactMap { label, signals in present.isDisjoint(with: signals) ? nil : label }
        return stages.isEmpty ? ["posture_inventory"] : stages
    }
}
