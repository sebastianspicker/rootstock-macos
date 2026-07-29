import Foundation
import RootstockCore

/// Multi-plane Wave-10 residual pair compound ranking (installer × extractor × stealer × visibility).
///
/// Research basis: engagement narrative across residual red↔blue pair themes.
/// Safety and behavior: deterministic compounds over CollectedState; not automated exploit orchestration.
public struct Wave10ResidualPairClusterCheck: Check {
    public static let id = "rootstock.check.vuln.wave10_residual_pair_cluster"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let planes = Self.pairPlanes(state: state)
        // Rank when ≥2 of the 4 residual pair planes are present.
        guard planes.count >= 2 else { return [] }
        return [Self.compoundFinding(planes: planes, state: state)]
    }

    /// The four residual pair planes only (no amplifiers counted toward the ≥2 gate).
    private static func pairPlanes(state: CollectedState) -> [String] {
        presentPlaneNames([
            .init(name: "installer_design", isPresent: installerDesignPresent(state)),
            .init(name: "archive_extractor", isPresent: archiveExtractorPresent(state)),
            .init(name: "stealer_paths", isPresent: stealerPathsPresent(state)),
            .init(name: "visibility_depth", isPresent: visibilityDepthPresent(state)),
        ])
    }


    private static func installerDesignPresent(_ state: CollectedState) -> Bool {
        let packageKit = state.packageKitInstallerDesign
        return packageKit?.designSurfacePresent == true
            || (packageKit?.installerServicePaths.count ?? 0) > 0
            || (packageKit?.receiptAndHistoryPaths.count ?? 0) >= 1
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
        return stealer?.collectionSurfacePresent == true
            || pathCount >= 3
            || ((stealer?.browserAdjacentPaths.count ?? 0) >= 1
                && (stealer?.messagingAndVaultPaths.count ?? 0) >= 1)
    }

    private static func visibilityDepthPresent(_ state: CollectedState) -> Bool {
        let visibility = state.tccEsfVisibilityDepth
        return visibility?.visibilitySurfacePresent == true
            || (visibility?.tccDbPathHits.count ?? 0) > 0
            || (visibility?.visibilityToolPaths.count ?? 0) > 0
            || visibility?.visibilityDepth == "thin"
            || visibility?.visibilityDepth == "partial"
    }

    private static func amplifiers(state: CollectedState) -> [String] {
        var amps: [String] = []
        let remote =
            state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true
        if remote { amps.append("remote") }
        if state.tcc?.fullDiskAccessLikely == true { amps.append("fda") }
        if state.protections?.sipEnabled == false { amps.append("sip_off") }
        if state.protections?.gatekeeperEnabled == false { amps.append("gk_off") }
        if let esf = state.esf, esf.clientPaths.isEmpty { amps.append("sensor_gap") }
        if state.securityProducts.filter(\.present).isEmpty { amps.append("products_absent") }
        return amps
    }

    private static func compoundFinding(planes: [String], state: CollectedState) -> Finding {
        let sorted = planes.sorted()
        let amps = amplifiers(state: state).sorted()
        return Finding(
            id: "\(id).multi_plane",
            title: compoundTitle(planes: sorted),
            severity: compoundSeverity(planes: sorted, amplifiers: amps),
            category: .misconfig,
            resolution: .init(
                evidence: compoundEvidence(planes: sorted, amplifiers: amps, state: state),
                attackTechniques: ["T1546", "T1553.001", "T1555", "T1562.001"],
                remediation: compoundRemediation,
                falsePositiveNotes: compoundFalsePositiveNotes
            ),
            runtime: .init(confidence: .low, dryRunSafe: true, opsecScore: 26, esfExpected: ["OPEN", "EXEC", "READ"])
        )
    }

    private static func compoundSeverity(planes: [String], amplifiers: [String]) -> Severity {
        if planes.contains("stealer_paths") && planes.contains("visibility_depth") && amplifiers.contains("fda") && amplifiers.contains("remote") { return .high }
        return planes.count >= 3 || (planes.count >= 2 && amplifiers.count >= 2) ? .medium : .low
    }

    private static func compoundTitle(planes: [String]) -> String {
        "Wave-10 residual-pair compound: \(planes.count) planes (\(planes.joined(separator: ", ")))"
    }

    private static func compoundEvidence(planes: [String], amplifiers: [String], state: CollectedState) -> [Evidence] {
        let stages = stageLabels(for: planes, amps: amplifiers)
        let amplifierDetail = amplifiers.isEmpty ? "amplifiers=none" : "amplifiers=\(amplifiers.joined(separator: "|")) count=\(amplifiers.count)"
        return [
            Evidence(type: "planes", detail: "planes=\(planes.joined(separator: "|")) count=\(planes.count)"),
            Evidence(type: "amplifiers", detail: amplifierDetail),
            Evidence(type: "stage_labels", detail: "stages=\(stages.joined(separator: "|")) (labels only - not auto-exploit)"),
            Evidence(type: "host", detail: "host=\(state.host?.hostname ?? "unknown") user=\(state.host?.username ?? "unknown")"),
            Evidence(type: "honesty", detail: "Wave-10 residual-pair ranking is path-to-impact narrative for operators. Rootstock Red does not build pkgs, craft Gatekeeper bypass archives, dump stealer secrets, dump TCC.db, or strip quarantine."),
        ]
    }

    private static let compoundRemediation = [
        "Prioritize hosts co-locating installer-design + stealer-paths + visibility-depth planes",
        "Close remote access and harden package/archive workflows before lower-tier inventory",
        "Use Wave-9 lab plans under ROE for purple validation of expected telemetry",
        "OPSEC: treat multi-plane compounds as engagement narrative, not an exploit script",
    ]

    private static let compoundFalsePositiveNotes = "Developer workstations may legitimately co-locate many residual pair planes. Rank production hosts with remote/FDA amplifiers first."

    private struct StageRule {
        let label: String
        let planes: Set<String>
        let amplifiers: Set<String>
    }

    private static func stageLabels(for planes: [String], amps: [String]) -> [String] {
        let rules = [
            StageRule(label: "delivery_trust", planes: ["archive_extractor"], amplifiers: ["gk_off"]),
            StageRule(label: "persistence_design", planes: ["installer_design"], amplifiers: []),
            StageRule(label: "collection_impact", planes: ["stealer_paths"], amplifiers: ["fda"]),
            StageRule(label: "detection_gap", planes: ["visibility_depth"], amplifiers: ["sensor_gap"]),
            StageRule(label: "lateral_path", planes: [], amplifiers: ["remote"]),
        ]
        let presentPlanes = Set(planes)
        let presentAmplifiers = Set(amps)
        let stages = rules.compactMap { rule in
            !presentPlanes.isDisjoint(with: rule.planes) || !presentAmplifiers.isDisjoint(with: rule.amplifiers)
                ? rule.label
                : nil
        }
        return stages.isEmpty ? ["posture_inventory"] : stages
    }
}
