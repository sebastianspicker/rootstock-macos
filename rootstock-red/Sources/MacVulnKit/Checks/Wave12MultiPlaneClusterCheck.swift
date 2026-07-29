import Foundation
import RootstockCore

/// Multi-plane Wave-12 compound ranking (6 net-new themes beyond Wave-11).
///
/// Research basis: engagement narrative across Wave-12 red↔blue pair themes.
/// Safety and behavior: deterministic compounds over CollectedState; not automated exploit orchestration.
public struct Wave12MultiPlaneClusterCheck: Check {
    public static let id = "rootstock.check.vuln.wave12_multi_plane_cluster"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let planes = Self.pairPlanes(state: state)
        guard planes.count >= 2 else { return [] }
        return [Self.compoundFinding(planes: planes, state: state)]
    }

    private static func pairPlanes(state: CollectedState) -> [String] {
        presentPlaneNames([
            .init(name: "webloc_inetloc", isPresent: hasPlaneSurface(state.weblocInetlocDelivery, isPresent: { $0.deliverySurfacePresent }, primaryCount: { $0.weblocSamplePaths.count }, secondaryCount: { $0.inetlocSamplePaths.count })),
            .init(name: "mail_rules", isPresent: hasPlaneSurface(state.mailRulesAutomation, isPresent: { $0.rulesSurfacePresent }, primaryCount: { $0.mailAppPaths.count }, secondaryCount: { $0.rulesPlistPaths.count })),
            .init(name: "unified_log", isPresent: hasPlaneSurface(state.unifiedLogObservation, isPresent: { $0.observationSurfacePresent }, primaryCount: { $0.logToolPaths.count }, secondaryCount: { $0.logarchiveHints.count })),
            .init(name: "dock_persist", isPresent: hasPlaneSurface(state.dockPersistenceSurface, isPresent: { $0.dockSurfacePresent }, primaryCount: { $0.dockPlistPaths.count }, secondaryCount: { $0.recentItemsPaths.count })),
            .init(name: "osascript_scpt", isPresent: hasPlaneSurface(state.osascriptScptDelivery, isPresent: { $0.scptSurfacePresent }, primaryCount: { $0.osaToolPaths.count }, secondaryCount: { $0.scriptEditorPaths.count })),
            .init(name: "network_share", isPresent: hasPlaneSurface(state.networkShareMount, isPresent: { $0.shareSurfacePresent }, primaryCount: { $0.smbClientPaths.count }, secondaryCount: { $0.netAuthPaths.count })),
        ])
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
        let severity: Severity
        if sorted.count >= 4 && amps.contains("remote") && amps.contains("fda") {
            severity = .high
        } else if sorted.count >= 3 || (sorted.count >= 2 && amps.count >= 2) {
            severity = .medium
        } else {
            severity = .low
        }

        return Finding(id: "\(id).multi_plane", title: "Wave-12 multi-plane compound: \(sorted.count) planes "
                + "(\(sorted.joined(separator: ", ")))", severity: severity, category: .misconfig, resolution: .init(evidence: [
                Evidence(
                    type: "planes",
                    detail: "planes=\(sorted.joined(separator: "|")) count=\(sorted.count)"
                ),
                Evidence(
                    type: "amplifiers",
                    detail:
                        amps.isEmpty
                        ? "amplifiers=none"
                        : "amplifiers=\(amps.joined(separator: "|")) count=\(amps.count)"
                ),
                Evidence(
                    type: "stage_labels",
                    detail: "stages=delivery|persist|visibility|lateral (labels only - not auto-exploit)"
                ),
                Evidence(
                    type: "host",
                    detail:
                        "host=\(state.host?.hostname ?? "unknown") "
                        + "user=\(state.host?.username ?? "unknown")"
                ),
                Evidence(
                    type: "honesty",
                    detail:
                        "Wave-12 multi-plane ranking is path-to-impact narrative. "
                        + "Rootstock Red does not craft webloc lures, modify Mail rules, dump unified logs, "
                        + "edit Dock.plist, compile malicious scpt, or mount attacker shares."
                ),
            ], attackTechniques: ["T1204", "T1114", "T1059.002", "T1021.002", "T1547", "T1083"], remediation: [
                "Prioritize hosts co-locating multiple Wave-12 planes with remote/FDA amplifiers",
                "Close remote access before deep dual-use inventory",
                "Use Wave-12 lab plans under ROE for purple validation",
                "OPSEC: multi-plane compounds are engagement narrative, not exploit scripts",
            ], falsePositiveNotes: "Developer workstations may legitimately co-locate many Wave-12 planes. "
                + "Rank production hosts with remote/FDA amplifiers first."), runtime: .init(confidence: .low, dryRunSafe: true, opsecScore: 28, esfExpected: ["OPEN", "EXEC", "READ"]))
    }
}
