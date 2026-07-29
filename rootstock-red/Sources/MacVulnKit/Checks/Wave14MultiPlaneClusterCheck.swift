import Foundation
import RootstockCore

/// Multi-plane Wave-14 compound ranking (10 net-new themes beyond Wave-13).
public struct Wave14MultiPlaneClusterCheck: Check {
    public static let id = "rootstock.check.vuln.wave14_multi_plane_cluster"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let planes = Self.pairPlanes(state: state)
        guard planes.count >= 2 else { return [] }
        return [Self.compoundFinding(planes: planes, state: state)]
    }
    private static func pairPlanes(state: CollectedState) -> [String] {
        automationPlanes(state) + systemIntegrationPlanes(state)
    }


    private static func automationPlanes(_ state: CollectedState) -> [String] {
        presentPlaneNames([
            .init(name: "automator_workflow", isPresent: hasPlaneSurface(state.automatorWorkflow, isPresent: { $0.workflowSurfacePresent }, primaryCount: { $0.automatorAppPaths.count }, secondaryCount: { $0.workflowSamplePaths.count })),
            .init(name: "icloud_drive_path", isPresent: hasPlaneSurface(state.icloudDrivePath, isPresent: { $0.icloudPathSurfacePresent }, primaryCount: { $0.mobileDocumentsPaths.count }, secondaryCount: { $0.icloudDrivePaths.count })),
            .init(name: "bluetooth_continuity_depth", isPresent: hasPlaneSurface(state.bluetoothContinuityDepth, isPresent: { $0.btContinuitySurfacePresent }, primaryCount: { $0.bluetoothDaemonPaths.count }, secondaryCount: { $0.continuitySupportPaths.count })),
            .init(name: "font_validation_dualuse", isPresent: hasPlaneSurface(state.fontValidationDualuse, isPresent: { $0.fontSurfacePresent }, primaryCount: { $0.fontToolPaths.count }, secondaryCount: { $0.atsSupportPaths.count })),
            .init(name: "quicklook_cache_depth", isPresent: hasPlaneSurface(state.quicklookCacheDepth, isPresent: { $0.quicklookSurfacePresent }, primaryCount: { $0.quicklookDaemonPaths.count }, secondaryCount: { $0.thumbnailCachePaths.count })),
        ])
    }

    private static func systemIntegrationPlanes(_ state: CollectedState) -> [String] {
        presentPlaneNames([
            .init(name: "dns_resolver_dualuse", isPresent: hasPlaneSurface(state.dnsResolverDualuse, isPresent: { $0.dnsSurfacePresent }, primaryCount: { $0.mdnsResponderPaths.count }, secondaryCount: { $0.resolverConfigPaths.count })),
            .init(name: "ls_quarantine_db_depth", isPresent: hasPlaneSurface(state.lsQuarantineDbDepth, isPresent: { $0.quarantineDbSurfacePresent }, primaryCount: { $0.quarantineDbPaths.count }, secondaryCount: { $0.lsSupportPaths.count })),
            .init(name: "pam_auth_module", isPresent: hasPlaneSurface(state.pamAuthModule, isPresent: { $0.pamSurfacePresent }, primaryCount: { $0.pamConfigPaths.count }, secondaryCount: { $0.pamModulePaths.count })),
            .init(name: "cron_at_job_depth", isPresent: hasPlaneSurface(state.cronAtJobDepth, isPresent: { $0.cronAtSurfacePresent }, primaryCount: { $0.cronBinaryPaths.count }, secondaryCount: { $0.crontabPaths.count })),
            .init(name: "notes_metadata_plane", isPresent: hasPlaneSurface(state.notesMetadataPlane, isPresent: { $0.notesSurfacePresent }, primaryCount: { $0.notesAppPaths.count }, secondaryCount: { $0.notesStorePaths.count })),
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
        return Finding(id: "\(id).multi_plane", title: "Wave-14 multi-plane compound: \(sorted.count) planes (\(sorted.joined(separator: ", ")))", severity: severity, category: .misconfig, resolution: .init(evidence: [
                Evidence(type: "planes", detail: "planes=\(sorted.joined(separator: "|")) count=\(sorted.count)"),
                Evidence(type: "amplifiers", detail: amps.isEmpty ? "amplifiers=none" : "amplifiers=\(amps.joined(separator: "|")) count=\(amps.count)"),
                Evidence(type: "stage_labels", detail: "stages=delivery|collection|auth|network|persist (labels only - not auto-exploit)"),
                Evidence(type: "host", detail: "host=\(state.host?.hostname ?? "unknown") user=\(state.host?.username ?? "unknown")"),
                Evidence(type: "honesty", detail: "Wave-14 multi-plane ranking is path-to-impact narrative. Rootstock Red does not execute Automator, dump iCloud/Notes contents, spoof Continuity, install fonts, rewrite DNS/PAM/cron, or clear QuarantineEvents."),
            ], attackTechniques: ["T1059", "T1530", "T1556", "T1053.003", "T1071.004", "T1553.001"], remediation: [
                "Prioritize hosts co-locating multiple Wave-14 planes with remote/FDA amplifiers",
                "Close remote access before deep dual-use inventory",
                "Use Wave-14 lab plans under ROE for purple validation",
                "OPSEC: multi-plane compounds are engagement narrative, not exploit scripts",
            ], falsePositiveNotes: "Developer workstations may co-locate many Wave-14 planes. Rank production remote hosts first."), runtime: .init(confidence: .low, dryRunSafe: true, opsecScore: 28, esfExpected: ["OPEN", "EXEC", "READ"]))
    }
}
