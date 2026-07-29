import Foundation
import RootstockCore

/// FileVault/escrow × Continuity × virtualization local data-protection cluster (Wave-7).
///
/// Research basis: local data confidentiality + proximity + nested execution research.
/// Safety and behavior: multi-rule ranked Findings; no key dump or proximity malware.
public struct LocalDataProtectionClusterCheck: Check {
    public static let id = "rootstock.check.vuln.local_data_protection_cluster"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        var findings: [Finding] = []
        if let f = Self.fvOffRemote(state: state) { findings.append(f) }
        if let f = Self.proximitySensitive(state: state) { findings.append(f) }
        if let f = Self.virtWithWeakDisk(state: state) { findings.append(f) }
        return findings
    }

    private static func fvOffRemote(state: CollectedState) -> Finding? {
        let fvOn = state.fileVaultEscrow?.fileVaultOn ?? state.protections?.fileVaultOn
        let remote =
            state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true
        guard fvOn == false && remote else { return nil }

        return Finding(id: "\(id).fv_off_remote", title: "Local data-protection cluster: FileVault off with remote access", severity: .high, category: .misconfig, resolution: .init(evidence: [
                Evidence(type: "fv", detail: "fileVaultOn=false"),
                Evidence(
                    type: "remote",
                    detail:
                        "ssh=\((state.network?.remoteLoginSSH).rootstockDescribe) "
                        + "ard=\((state.network?.screenSharingARD).rootstockDescribe)"
                ),
            ], attackTechniques: ["T1021", "T1552"], remediation: [
                "Enable FileVault before exposing SSH/ARD",
                "Restrict remote access via MDM network policies",
            ]), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 14, esfExpected: ["OPEN"]))
    }

    private static func proximitySensitive(state: CollectedState) -> Finding? {
        let surface = state.continuityAirDrop?.proximitySurfacePresent == true
            || (state.continuityAirDrop?.airdropPrefPaths.count ?? 0) > 0
            || state.collectorNotes["collect.continuity_airdrop"] != nil
        let sensitive =
            state.browserMeta.contains(where: \.exists)
            || state.credPaths.contains(where: \.exists)
            || state.tcc?.fullDiskAccessLikely == true
        guard surface && sensitive else { return nil }

        return Finding(id: "\(id).proximity_sensitive", title: "Local data-protection cluster: proximity transfer surface near sensitive path inventory", severity: .medium, category: .network, resolution: .init(evidence: [
                Evidence(
                    type: "proximity",
                    detail:
                        "airdropPrefs=\(state.continuityAirDrop?.airdropPrefPaths.count ?? 0) "
                        + "continuity=\(state.continuityAirDrop?.continuityFrameworkPaths.count ?? 0)"
                ),
                Evidence(
                    type: "sensitive",
                    detail:
                        "browserMetaExists=\(state.browserMeta.filter(\.exists).count) "
                        + "credPaths=\(state.credPaths.filter(\.exists).count) "
                        + "fda=\((state.tcc?.fullDiskAccessLikely).rootstockDescribe)"
                ),
            ], attackTechniques: ["T1091", "T1005"], remediation: [
                "Disable open AirDrop receive on high-value hosts",
                "Minimize FDA grants; protect session artifact paths",
            ]), runtime: .init(confidence: .low, dryRunSafe: true, opsecScore: 15, tccDomains: state.tcc?.fullDiskAccessLikely == true ? ["FullDiskAccess"] : [], esfExpected: ["OPEN"]))
    }

    private static func virtWithWeakDisk(state: CollectedState) -> Finding? {
        let dual = state.virtualizationContainers?.dualUsePresent == true
            || (state.virtualizationContainers?.containerToolPaths.count ?? 0) > 0
            || (state.virtualizationContainers?.hypervisorAppPaths.count ?? 0) > 0
        let fvOn = state.fileVaultEscrow?.fileVaultOn ?? state.protections?.fileVaultOn
        let sipOff = state.protections?.sipEnabled == false
        guard dual && (fvOn == false || sipOff) else { return nil }

        return Finding(id: "\(id).virt_weak_disk", title: "Local data-protection cluster: virt/container dual-use with weak disk/SIP posture", severity: .medium, category: .lool, resolution: .init(evidence: [
                Evidence(
                    type: "virt",
                    detail:
                        "containers=\(state.virtualizationContainers?.containerToolPaths.count ?? 0) "
                        + "hypervisors=\(state.virtualizationContainers?.hypervisorAppPaths.count ?? 0)"
                ),
                Evidence(
                    type: "disk",
                    detail: "fileVaultOn=\(fvOn.rootstockDescribe) sipEnabled=\((state.protections?.sipEnabled).rootstockDescribe)"
                ),
            ], attackTechniques: ["T1564", "T1610"], remediation: [
                "Require FileVault on hosts with Docker/VM tooling",
                "Keep SIP enabled; isolate nested-execution workstations",
            ]), runtime: .init(confidence: .low, dryRunSafe: true, opsecScore: 18, esfExpected: ["OPEN", "EXEC"]))
    }

}
