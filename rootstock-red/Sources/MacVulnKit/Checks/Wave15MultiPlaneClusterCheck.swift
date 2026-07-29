import Foundation
import RootstockCore

/// Multi-plane Wave-15 compound ranking (10 net-new themes beyond Wave-14).
public struct Wave15MultiPlaneClusterCheck: Check {
    public static let id = "rootstock.check.vuln.wave15_multi_plane_cluster"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let planes = Self.pairPlanes(state: state)
        guard planes.count >= 2 else { return [] }
        return [Self.compoundFinding(planes: planes, state: state)]
    }
    private static func pairPlanes(state: CollectedState) -> [String] {
        hostSurfacePlanes(state) + persistencePlanes(state)
    }


    private static func hostSurfacePlanes(_ state: CollectedState) -> [String] {
        presentPlaneNames([
            .init(name: "photos_library_path", isPresent: hasPlaneSurface(state.photosLibraryPath, isPresent: { $0.photosSurfacePresent }, primaryCount: { $0.photosAppPaths.count }, secondaryCount: { $0.photosLibraryPaths.count })),
            .init(name: "vpn_config_dualuse", isPresent: hasPlaneSurface(state.vpnConfigDualuse, isPresent: { $0.vpnSurfacePresent }, primaryCount: { $0.vpnFrameworkPaths.count }, secondaryCount: { $0.vpnPrefPaths.count })),
            .init(name: "sandbox_container_depth", isPresent: hasPlaneSurface(state.sandboxContainerDepth, isPresent: { $0.sandboxSurfacePresent }, primaryCount: { $0.containerRootPaths.count }, secondaryCount: { $0.sandboxProfilePaths.count })),
            .init(name: "xpc_mach_service_depth", isPresent: hasPlaneSurface(state.xpcMachServiceDepth, isPresent: { $0.xpcMachSurfacePresent }, primaryCount: { $0.xpcBootstrapPaths.count }, secondaryCount: { $0.machServicePlistPaths.count })),
            .init(name: "tm_local_snapshot_depth", isPresent: hasPlaneSurface(state.tmLocalSnapshotDepth, isPresent: { $0.tmSnapshotSurfacePresent }, primaryCount: { $0.tmUtilPaths.count }, secondaryCount: { $0.snapshotStorePaths.count })),
        ])
    }

    private static func persistencePlanes(_ state: CollectedState) -> [String] {
        presentPlaneNames([
            .init(name: "emond_legacy_depth", isPresent: hasPlaneSurface(state.emondLegacyDepth, isPresent: { $0.emondSurfacePresent }, primaryCount: { $0.emondBinaryPaths.count }, secondaryCount: { $0.emondRulePaths.count })),
            .init(name: "screen_sharing_ard_depth", isPresent: hasPlaneSurface(state.screenSharingArdDepth, isPresent: { $0.ardSurfacePresent }, primaryCount: { $0.screenSharingAppPaths.count }, secondaryCount: { $0.ardAgentPaths.count })),
            .init(name: "keychain_acl_path", isPresent: hasPlaneSurface(state.keychainAclPath, isPresent: { $0.keychainAclSurfacePresent }, primaryCount: { $0.keychainDbPaths.count }, secondaryCount: { $0.securityToolPaths.count })),
            .init(name: "python_runtime_dualuse", isPresent: hasPlaneSurface(state.pythonRuntimeDualuse, isPresent: { $0.pythonSurfacePresent }, primaryCount: { $0.pythonBinaryPaths.count }, secondaryCount: { $0.sitePackagePaths.count })),
            .init(name: "shell_plugin_manager", isPresent: hasPlaneSurface(state.shellPluginManager, isPresent: { $0.shellPluginSurfacePresent }, primaryCount: { $0.omzPaths.count }, secondaryCount: { $0.pluginDirPaths.count })),
        ])
    }
    private static func amplifiers(state: CollectedState) -> [String] {
        var amps: [String] = []
        if state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true { amps.append("remote") }
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
        let severity: Severity = (sorted.count >= 5 && amps.contains("remote") && amps.contains("fda")) ? .high
            : ((sorted.count >= 3 || (sorted.count >= 2 && amps.count >= 2)) ? .medium : .low)
        return Finding(id: "\(id).multi_plane", title: "Wave-15 multi-plane compound: \(sorted.count) planes (\(sorted.joined(separator: ", ")))", severity: severity, category: .misconfig, resolution: .init(evidence: [
                Evidence(type: "planes", detail: "planes=\(sorted.joined(separator: "|")) count=\(sorted.count)"),
                Evidence(type: "amplifiers", detail: amps.isEmpty ? "amplifiers=none" : "amplifiers=\(amps.joined(separator: "|")) count=\(amps.count)"),
                Evidence(type: "stage_labels", detail: "stages=collection|remote|sandbox|lolbin|persist (labels only - not auto-exploit)"),
                Evidence(type: "host", detail: "host=\(state.host?.hostname ?? "unknown") user=\(state.host?.username ?? "unknown")"),
                Evidence(type: "honesty", detail: "Wave-15 multi-plane ranking is path-to-impact narrative. Rootstock Red does not dump Photos/keychain secrets, enable ARD/VPN, break sandbox, install emond/cron, or run Python/shell plugin payloads."),
            ], attackTechniques: ["T1005", "T1021", "T1555.001", "T1059.006", "T1546.004", "T1546.014"], remediation: [
                "Prioritize hosts co-locating multiple Wave-15 planes with remote/FDA amplifiers",
                "Close remote access before deep dual-use inventory",
                "Use Wave-15 lab plans under ROE for purple validation",
                "OPSEC: multi-plane compounds are engagement narrative, not exploit scripts",
            ], falsePositiveNotes: "Developer workstations may co-locate many Wave-15 planes. Rank production remote hosts first."), runtime: .init(confidence: .low, dryRunSafe: true, opsecScore: 28, esfExpected: ["OPEN", "EXEC", "READ"]))
    }
}
