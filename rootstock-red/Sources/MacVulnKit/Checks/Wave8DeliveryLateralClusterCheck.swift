import Foundation
import RootstockCore

/// Multi-plane Wave-8 delivery × lateral compound ranking.
///
/// Research basis: engagement narrative across ClickFix delivery, RAE lateral, data-access, mgmt plane, SSH depth.
/// Safety and behavior: deterministic compounds over CollectedState; not automated exploit orchestration.
public struct Wave8DeliveryLateralClusterCheck: Check {
    public static let id = "rootstock.check.vuln.wave8_delivery_lateral_cluster"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let planes = Self.planeSignals(state: state)
        guard planes.count >= 2 else { return [] }
        return [Self.compoundFinding(planes: planes, state: state)]
    }

    private static func planeSignals(state: CollectedState) -> [String] {
        presentPlaneNames([
            .init(name: "clickfix_delivery", isPresent: clickFixPresent(state)),
            .init(name: "rae_lateral", isPresent: remoteAppleEventsPresent(state)),
            .init(name: "spotlight_cache", isPresent: spotlightCachePresent(state)),
            .init(name: "sec_mgmt_plane", isPresent: securityManagementPresent(state)),
            .init(name: "tcc_inheritance", isPresent: tccInheritancePresent(state)),
            .init(name: "ssh_key_depth", isPresent: sshKeyDepthPresent(state)),
            .init(name: "remote", isPresent: remoteAccessPresent(state)),
            .init(name: "sensor_gap", isPresent: sensorGapPresent(state)),
            .init(name: "fda", isPresent: fullDiskAccessPresent(state)),
        ])
    }


    private static func clickFixPresent(_ state: CollectedState) -> Bool {
        let click = state.clickFixTerminalDelivery
        return click?.deliverySurfacePresent == true
            || (click?.loaderBinaryPaths.count ?? 0) >= 2
            || (click?.terminalAppPaths.count ?? 0) + (click?.scriptEditorPaths.count ?? 0) >= 2
    }

    private static func remoteAppleEventsPresent(_ state: CollectedState) -> Bool {
        let events = state.remoteAppleEvents
        return events?.remoteAutomationSurfacePresent == true
            || (events?.remoteAEPrefPaths.count ?? 0) > 0
            || (events?.eppcFrameworkPaths.count ?? 0) >= 2
    }

    private static func spotlightCachePresent(_ state: CollectedState) -> Bool {
        let spotlight = state.spotlightAICache
        return spotlight?.dataAccessSurfacePresent == true
            || (spotlight?.spotlightPaths.count ?? 0) > 0
            || (spotlight?.metadataFrameworkPaths.count ?? 0) > 0
            || (spotlight?.aiCachePathHints.count ?? 0) > 0
    }

    private static func securityManagementPresent(_ state: CollectedState) -> Bool {
        let management = state.securityMgmtPlane
        return management?.managementPlanePresent == true
            || (management?.managementCLIPaths.count ?? 0) > 0
            || (management?.privilegedHelperPaths.count ?? 0) > 0
    }

    private static func tccInheritancePresent(_ state: CollectedState) -> Bool {
        let inheritance = state.thirdPartyTCCInheritance
        return inheritance?.inheritanceSurfacePresent == true
            || (inheritance?.thickClientAppPaths.count ?? 0) > 0
            || (inheritance?.embeddedInterpreterPaths.count ?? 0) > 0
    }

    private static func sshKeyDepthPresent(_ state: CollectedState) -> Bool {
        let ssh = state.sshAgentKeyPath
        return ssh?.lateralPathSurfacePresent == true
            || (ssh?.keyPathHits.count ?? 0) > 0
            || (ssh?.agentSocketPaths.count ?? 0) > 0
    }

    private static func remoteAccessPresent(_ state: CollectedState) -> Bool {
        state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
    }

    private static func sensorGapPresent(_ state: CollectedState) -> Bool {
        state.esf?.clientPaths.isEmpty == true
    }

    private static func fullDiskAccessPresent(_ state: CollectedState) -> Bool {
        state.tcc?.fullDiskAccessLikely == true
    }

    private static func compoundFinding(planes: [String], state: CollectedState) -> Finding {
        let sorted = planes.sorted()
        return Finding(
            id: "\(id).multi_plane",
            title: compoundTitle(for: sorted),
            severity: compoundSeverity(for: sorted),
            category: .misconfig,
            resolution: compoundResolution(for: sorted, state: state),
            runtime: .init(confidence: .low, dryRunSafe: true, opsecScore: 22, esfExpected: ["OPEN", "EXEC"])
        )
    }

    private static func compoundTitle(for planes: [String]) -> String {
        "Wave-8 delivery×lateral compound: \(planes.count) planes "
            + "(\(planes.prefix(5).joined(separator: ", "))\(planes.count > 5 ? ", …" : ""))"
    }

    private static func compoundSeverity(for planes: [String]) -> Severity {
        if planes.contains("clickfix_delivery") && planes.contains("remote") && planes.count >= 4 {
            return .high
        }
        return planes.contains("remote") && planes.count >= 3 || planes.count >= 4 ? .medium : .low
    }

    private static func compoundResolution(for planes: [String], state: CollectedState) -> Finding.Resolution {
        let stageHints = stageLabels(for: planes)
        var resolution = Finding.Resolution()
        resolution.evidence = [
            Evidence(type: "planes", detail: "planes=\(planes.joined(separator: "|")) count=\(planes.count)"),
            Evidence(type: "stage_labels", detail: "stages=\(stageHints.joined(separator: "|")) (labels only - not auto-exploit)"),
            Evidence(type: "host", detail: "host=\(state.host?.hostname ?? "unknown") user=\(state.host?.username ?? "unknown")"),
            Evidence(type: "honesty", detail: "Wave-8 compound ranking is path-to-impact narrative for operators. Rootstock Red does not orchestrate ClickFix, RAE lateral, EDR unload, or SSH key extraction."),
        ]
        resolution.attackTechniques = ["T1204.002", "T1021", "T1005", "T1562.001"]
        resolution.remediation = [
            "Prioritize co-occurring delivery + remote + sensor-gap planes on tier-0 hosts",
            "Close remote access and harden paste-run user awareness before lower-tier inventory",
            "Use lab plans under ROE for purple validation of expected telemetry",
            "OPSEC: treat multi-plane compounds as engagement narrative, not an exploit script",
        ]
        resolution.falsePositiveNotes = "Developer workstations may legitimately co-locate many Wave-8 planes. Rank production hosts first."
        return resolution
    }

    private static func stageLabels(for planes: [String]) -> [String] {
        let rules: [(label: String, planes: Set<String>)] = [
            ("initial_access_delivery", ["clickfix_delivery"]),
            ("lateral_path", ["rae_lateral", "ssh_key_depth", "remote"]),
            ("collection_impact", ["spotlight_cache", "fda"]),
            ("capability_inheritance", ["tcc_inheritance"]),
            ("detection_gap", ["sec_mgmt_plane", "sensor_gap"]),
        ]
        let presentPlanes = Set(planes)
        let stages = rules.compactMap { rule in
            !presentPlanes.isDisjoint(with: rule.planes) ? rule.label : nil
        }
        return stages.isEmpty ? ["posture_inventory"] : stages
    }
}
