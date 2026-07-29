import Foundation
import RootstockCore

/// Path-to-impact: multi-domain TCC permission graph depth (beyond FDA-only).
///
/// Research basis: SwiftBelt domain probes; Screen/AX/Automation research.
/// Safety and behavior: graph of domain signals with compound severity; no TCC.db dump; no prompts.
public struct TCCPermissionGraphDepthVector: Check {
    public static let id = "rootstock.vector.tcc.permission_graph_depth"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        guard let tcc = state.tcc else { return [] }
        let profile = Self.signalProfile(tcc: tcc)
        guard Self.shouldEmit(profile: profile, state: state) else { return [] }
        return [Self.finding(profile: profile, tcc: tcc, state: state)]
    }

    private struct SignalProfile {
        let signals: [String]
        let fdaLikely: Bool
        let automation: Bool
        let screen: Bool
        let filesFolders: Bool
        var interestingCount: Int { [fdaLikely, automation, screen, filesFolders].filter { $0 }.count }
        var domains: [String] { [fdaLikely ? "FullDiskAccess" : nil, automation ? "Automation" : nil, screen ? "ScreenCapture" : nil, filesFolders ? "FilesAndFolders" : nil].compactMap { $0 } }
    }

    private static func signalProfile(tcc: TCCState) -> SignalProfile {
        let signals = tcc.domainSignals
        return SignalProfile(signals: signals, fdaLikely: tcc.fullDiskAccessLikely == true || signals.contains { $0.localizedCaseInsensitiveContains("FullDiskAccess=likely") }, automation: signals.contains { $0.localizedCaseInsensitiveContains("Automation=osascript_present") }, screen: signals.contains { $0.localizedCaseInsensitiveContains("ScreenCapture=tool_present") || $0.localizedCaseInsensitiveContains("screen_recording=tool_present") }, filesFolders: signals.contains { $0.contains("FilesAndFolders=") && !$0.contains("none_listable") })
    }

    private static func shouldEmit(profile: SignalProfile, state: CollectedState) -> Bool {
        let hasInventory = profile.signals.count >= 2 || state.collectorNotes["collect.tcc_permission_graph"] != nil
        return hasInventory && (profile.interestingCount >= 2 || (profile.fdaLikely && !profile.signals.isEmpty) || profile.signals.count >= 4)
    }

    private static func finding(profile: SignalProfile, tcc: TCCState, state: CollectedState) -> Finding {
        var evidence = [Evidence(type: "probe", detail: "method=\(tcc.probeMethod)"), Evidence(type: "domain_graph", detail: profile.signals.isEmpty ? "(from notes)" : profile.signals.joined(separator: ";"))]
        evidence += profile.signals.prefix(16).map { Evidence(type: "domain_signal", detail: $0) }
        evidence += tcc.notes.prefix(10).map { Evidence(type: "tcc_note", detail: $0) }
        if state.browserMeta.contains(where: \.exists) || state.credPaths.contains(where: \.exists) { evidence.append(Evidence(type: "pivot_targets", detail: "browserMetaPresent=\(state.browserMeta.filter(\.exists).count) credPathsPresent=\(state.credPaths.filter(\.exists).count) (metadata only - no secret material)")) }
        let severity: Severity = profile.fdaLikely && (profile.automation || profile.screen) ? .high : profile.interestingCount >= 3 ? .medium : .low
        let title = severity == .high ? "TCC graph depth: FDA plus Automation/Screen domain signals" : severity == .medium ? "TCC graph depth: multi-domain permission surface (\(profile.interestingCount) domains)" : "TCC permission graph surface (\(profile.signals.count) domain signals)"
        return Finding(id: Self.id, title: title, severity: severity, category: .tcc, resolution: .init(evidence: evidence, attackTechniques: ["T1069", "T1005", "T1113", "T1059.002", "T1083"], remediation: ["Review System Settings → Privacy & Security grants per domain (FDA, Automation, Screen, AX)", "Deploy PPPC profiles for enterprise allowlists; revoke unexpected grants", "Treat multi-domain grant combinations as higher impact than single booleans", "OPSEC: assess uses non-prompting probes only - never force TCC dialogs"], falsePositiveNotes: "Domain signals are heuristics (tool presence / path listability), not live TCC.db grants. MDM PPPC may grant outside user-visible settings."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: profile.fdaLikely ? 38 : 24, tccDomains: profile.domains.isEmpty ? ["FullDiskAccess"] : profile.domains, esfExpected: ["OPEN"]))
    }
}
