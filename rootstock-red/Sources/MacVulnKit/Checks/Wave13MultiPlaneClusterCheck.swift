import Foundation
import RootstockCore

/// Multi-plane Wave-13 compound ranking (5 net-new themes beyond Wave-12).
public struct Wave13MultiPlaneClusterCheck: Check {
    public static let id = "rootstock.check.vuln.wave13_multi_plane_cluster"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let planes = Self.pairPlanes(state: state)
        guard planes.count >= 2 else { return [] }
        return [Self.compoundFinding(planes: planes, state: state)]
    }
    private static func pairPlanes(state: CollectedState) -> [String] {
        presentPlaneNames([
            .init(name: "calendar_reminders", isPresent: hasPlaneSurface(state.calendarRemindersAutomation, isPresent: { $0.automationSurfacePresent }, primaryCount: { $0.calendarAppPaths.count }, secondaryCount: { $0.remindersPaths.count })),
            .init(name: "gk_assessment", isPresent: hasPlaneSurface(state.gatekeeperAssessmentHistory, isPresent: { $0.assessmentSurfacePresent }, primaryCount: { $0.syspolicydPaths.count }, secondaryCount: { $0.assessmentDbPaths.count })),
            .init(name: "homebrew_pkg", isPresent: hasPlaneSurface(state.homebrewPackageDualUse, isPresent: { $0.packageSurfacePresent }, primaryCount: { $0.brewBinaryPaths.count }, secondaryCount: { $0.cellarPaths.count })),
            .init(name: "cups_print", isPresent: hasPlaneSurface(state.cupsPrintDualUse, isPresent: { $0.printSurfacePresent }, primaryCount: { $0.cupsDaemonPaths.count }, secondaryCount: { $0.ppdConfigPaths.count })),
            .init(name: "screencapture", isPresent: hasPlaneSurface(state.screenCapturePrivacyDualUse, isPresent: { $0.captureSurfacePresent }, primaryCount: { $0.screencaptureToolPaths.count }, secondaryCount: { $0.screenCaptureKitPaths.count })),
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
        let severity: Severity = (sorted.count >= 4 && amps.contains("remote") && amps.contains("fda")) ? .high
            : ((sorted.count >= 3 || (sorted.count >= 2 && amps.count >= 2)) ? .medium : .low)
        return Finding(id: "\(id).multi_plane", title: "Wave-13 multi-plane compound: \(sorted.count) planes (\(sorted.joined(separator: ", ")))", severity: severity, category: .misconfig, resolution: .init(evidence: [
                Evidence(type: "planes", detail: "planes=\(sorted.joined(separator: "|")) count=\(sorted.count)"),
                Evidence(type: "amplifiers", detail: amps.isEmpty ? "amplifiers=none" : "amplifiers=\(amps.joined(separator: "|")) count=\(amps.count)"),
                Evidence(type: "stage_labels", detail: "stages=automation|delivery_trust|dual_use|collection|print (labels only - not auto-exploit)"),
                Evidence(type: "host", detail: "host=\(state.host?.hostname ?? "unknown") user=\(state.host?.username ?? "unknown")"),
                Evidence(type: "honesty", detail: "Wave-13 multi-plane ranking is path-to-impact narrative. Rootstock Red does not capture screens, clear Gatekeeper history, install brew packages, reconfigure CUPS, or forge calendar invites."),
            ], attackTechniques: ["T1059", "T1553.001", "T1072", "T1113", "T1040"], remediation: [
                "Prioritize hosts co-locating multiple Wave-13 planes with remote/FDA amplifiers",
                "Close remote access before deep dual-use inventory",
                "Use Wave-13 lab plans under ROE for purple validation",
                "OPSEC: multi-plane compounds are engagement narrative, not exploit scripts",
            ], falsePositiveNotes: "Developer workstations may co-locate many Wave-13 planes. Rank production remote hosts first."), runtime: .init(confidence: .low, dryRunSafe: true, opsecScore: 28, esfExpected: ["OPEN", "EXEC", "READ"]))
    }
}
