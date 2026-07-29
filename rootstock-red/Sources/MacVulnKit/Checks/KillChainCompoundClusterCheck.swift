import Foundation
import RootstockCore

/// Multi-plane kill-chain compound ranking (Wave-7).
///
/// Research basis: engagement narrative ranking across foothold/trust/privilege/collection.
/// Safety and behavior: deterministic compounds over CollectedState; not automated exploit orchestration.
public struct KillChainCompoundClusterCheck: Check {
    public static let id = "rootstock.check.vuln.kill_chain_compound_cluster"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let planes = Self.planeSignals(state: state)
        guard planes.count >= 3 else {
            // Still emit a lighter compound when 2 high-value planes co-occur with remote
            if planes.count >= 2 && planes.contains("remote") {
                return [Self.compoundFinding(planes: planes, state: state)]
            }
            return []
        }
        return [Self.compoundFinding(planes: planes, state: state)]
    }

    /// Stable plane labels for ranking (deterministic order).
    private static func planeSignals(state: CollectedState) -> [String] {
        presentPlaneNames([
            .init(name: "remote", isPresent: remotePresent(state)),
            .init(name: "protections_weak", isPresent: protectionsWeak(state)),
            .init(name: "tcc_depth", isPresent: tccDepthPresent(state)),
            .init(name: "inject_trust", isPresent: injectTrustPresent(state)),
            .init(name: "sandbox_thick_client", isPresent: sandboxPresent(state)),
            .init(name: "notarization_delivery", isPresent: notarizationPresent(state)),
            .init(name: "virt_dual_use", isPresent: virtualizationPresent(state)),
            .init(name: "proximity", isPresent: proximityPresent(state)),
            .init(name: "filevault_escrow", isPresent: fileVaultEscrowPresent(state)),
            .init(name: "sensor_gap", isPresent: sensorGapPresent(state)),
            .init(name: "collection_paths", isPresent: collectionPathsPresent(state)),
            .init(name: "dev_toolchain", isPresent: developerToolchainPresent(state)),
        ])
    }


    private static func remotePresent(_ state: CollectedState) -> Bool {
        state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
    }

    private static func protectionsWeak(_ state: CollectedState) -> Bool {
        state.protections?.sipEnabled == false || state.protections?.gatekeeperEnabled == false
    }

    private static func tccDepthPresent(_ state: CollectedState) -> Bool {
        state.tcc?.fullDiskAccessLikely == true || (state.tcc?.domainSignals.count ?? 0) >= 3
    }

    private static func injectTrustPresent(_ state: CollectedState) -> Bool {
        !state.injectabilityHits.filter { !$0.riskFlags.isEmpty }.isEmpty
            || state.codesignSamples.contains(where: { $0.getTaskAllow == true })
    }

    private static func sandboxPresent(_ state: CollectedState) -> Bool {
        (state.appSandboxEntitlements?.appSamples.count ?? 0) > 0
            || (state.appSandboxEntitlements?.unsandboxedRiskPaths.count ?? 0) > 0
            || state.collectorNotes["collect.app_sandbox_entitlements"] != nil
    }

    private static func notarizationPresent(_ state: CollectedState) -> Bool {
        (state.notarizationStapling?.unstapledOrAdHocHints.count ?? 0) > 0
            || state.collectorNotes["collect.notarization_stapling"] != nil
    }

    private static func virtualizationPresent(_ state: CollectedState) -> Bool {
        state.virtualizationContainers?.dualUsePresent == true
            || (state.virtualizationContainers?.containerToolPaths.count ?? 0) > 0
            || (state.virtualizationContainers?.hypervisorAppPaths.count ?? 0) > 0
    }

    private static func proximityPresent(_ state: CollectedState) -> Bool {
        state.continuityAirDrop?.proximitySurfacePresent == true
            || (state.continuityAirDrop?.airdropPrefPaths.count ?? 0) > 0
    }

    private static func fileVaultEscrowPresent(_ state: CollectedState) -> Bool {
        let fileVaultOn = state.fileVaultEscrow?.fileVaultOn ?? state.protections?.fileVaultOn
        return fileVaultOn == false
            || (state.fileVaultEscrow?.escrowPathHints.count ?? 0) > 0
            || state.collectorNotes["collect.filevault_escrow"] != nil
    }

    private static func sensorGapPresent(_ state: CollectedState) -> Bool {
        state.esf?.clientPaths.isEmpty == true
            || (state.securityProducts.filter(\.present).isEmpty
                && state.collectorNotes["collect.esf_endpoint_security"] != nil)
    }

    private static func collectionPathsPresent(_ state: CollectedState) -> Bool {
        state.credPaths.contains(where: \.exists) || state.browserMeta.contains(where: \.exists)
    }

    private static func developerToolchainPresent(_ state: CollectedState) -> Bool {
        state.developerToolchain?.xcodePresent == true
            || !(state.developerToolchain?.dualUseBinaries.isEmpty ?? true)
    }

    private static func compoundFinding(planes: [String], state: CollectedState) -> Finding {
        let sorted = planes.sorted()
        return Finding(
            id: "\(id).multi_plane",
            title: compoundTitle(planes: sorted),
            severity: compoundSeverity(planes: sorted),
            category: .misconfig,
            resolution: .init(
                evidence: compoundEvidence(planes: sorted, state: state),
                attackTechniques: ["T1082", "T1016", "T1021", "T1553"],
                remediation: [
                    "Prioritize remediation of co-occurring high-severity planes (remote + protections + sensor gap)",
                    "Close remote access before addressing lower-tier inventory findings",
                    "Use lab plans under ROE for purple validation of expected telemetry",
                    "OPSEC: treat multi-plane compounds as engagement narrative, not an exploit script",
                ],
                falsePositiveNotes: "Developer workstations may legitimately co-locate many planes. Rank production/tier-0 hosts first."
            ),
            runtime: .init(confidence: .low, dryRunSafe: true, opsecScore: 22, esfExpected: ["OPEN", "EXEC"])
        )
    }

    private static func compoundSeverity(planes: [String]) -> Severity {
        if planes.contains("remote") && planes.contains("protections_weak") && planes.count >= 4 { return .high }
        return planes.contains("remote") && planes.count >= 3 || planes.count >= 5 ? .medium : .low
    }

    private static func compoundTitle(planes: [String]) -> String {
        let suffix = planes.count > 5 ? ", …" : ""
        return "Kill-chain compound: \(planes.count) posture planes co-occur (\(planes.prefix(5).joined(separator: ", "))\(suffix))"
    }

    private static func compoundEvidence(planes: [String], state: CollectedState) -> [Evidence] {
        let stages = stageLabels(for: planes)
        return [
            Evidence(type: "planes", detail: "planes=\(planes.joined(separator: "|")) count=\(planes.count)"),
            Evidence(type: "stage_labels", detail: "stages=\(stages.joined(separator: "|")) (labels only - not auto-exploit)"),
            Evidence(type: "host", detail: "host=\(state.host?.hostname ?? "unknown") user=\(state.host?.username ?? "unknown")"),
            Evidence(type: "honesty", detail: "Kill-chain ranking is path-to-impact narrative for operators. Rootstock Red does not orchestrate multi-stage implants or 0-day packs."),
        ]
    }

    private static func stageLabels(for planes: [String]) -> [String] {
        let present = Set(planes)
        let definitions = [
            ("foothold_adjacent", ["remote", "proximity"]),
            ("trust_gap", ["inject_trust", "sandbox_thick_client", "notarization_delivery", "protections_weak"]),
            ("privilege_or_capability", ["tcc_depth", "dev_toolchain", "virt_dual_use"]),
            ("collection_impact", ["collection_paths", "filevault_escrow"]),
            ("detection_gap", ["sensor_gap"]),
        ]
        let stages = definitions.compactMap { label, signals in
            present.isDisjoint(with: signals) ? nil : label
        }
        return stages.isEmpty ? ["posture_inventory"] : stages
    }
}
