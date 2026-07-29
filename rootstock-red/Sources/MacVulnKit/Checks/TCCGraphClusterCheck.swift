import Foundation
import RootstockCore

/// TCC multi-domain graph cluster.
///
/// Research basis: SwiftBelt/PEASS TCC themes.
/// Safety and behavior: domain compound rules; no TCC.db dump.
public struct TCCGraphClusterCheck: Check {
    public static let id = "rootstock.check.vuln.tcc_graph_cluster"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        var findings: [Finding] = []
        if let f = Self.fdaPlusBrowser(state: state) { findings.append(f) }
        if let f = Self.automationPlusPersistBins(state: state) { findings.append(f) }
        if let f = Self.screenPlusRemote(state: state) { findings.append(f) }
        return findings
    }

    private static func fdaPlusBrowser(state: CollectedState) -> Finding? {
        guard state.tcc?.fullDiskAccessLikely == true else { return nil }
        let browsers = state.browserMeta.filter(\.exists)
        guard !browsers.isEmpty else { return nil }

        return Finding(id: "\(id).fda_plus_browser_meta", title: "TCC graph cluster: FDA likely with browser session metadata paths", severity: .high, category: .tcc, resolution: .init(evidence: [
                Evidence(type: "fda", detail: "fullDiskAccessLikely=true"),
                Evidence(
                    type: "browser_meta",
                    detail: "present=\(browsers.count) (paths only - no cookie/password rows)"
                ),
            ], attackTechniques: ["T1530", "T1005", "T1083"], remediation: [
                "Revoke unexpected FDA; prefer PPPC allowlists",
                "Browser DBs remain high-value even when assess never reads rows",
            ]), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 36, tccDomains: ["FullDiskAccess"], esfExpected: ["OPEN"]))
    }

    private static func automationPlusPersistBins(state: CollectedState) -> Finding? {
        let signals = state.tcc?.domainSignals ?? []
        let automation =
            signals.contains { $0.localizedCaseInsensitiveContains("Automation=osascript_present") }
            || state.loobins.contains { $0.present && $0.name.lowercased() == "osascript" }
        let launchctl = state.loobins.contains {
            $0.present && $0.name.lowercased() == "launchctl"
        }
        guard automation && launchctl else { return nil }

        return Finding(id: "\(id).automation_persist_bins", title: "TCC graph cluster: Automation (osascript) + launchctl dual-use pair", severity: .medium, category: .tcc, resolution: .init(evidence: [
                Evidence(type: "automation", detail: "osascript present"),
                Evidence(type: "persist", detail: "launchctl present"),
                Evidence(
                    type: "note",
                    detail: "Stock dual-use pair - path-to-impact is chain utility, not malware"
                ),
            ], attackTechniques: ["T1059.002", "T1543.001"], remediation: [
                "Monitor osascript → launchctl process trees in EDR",
                "Require justification for Automation grants to third-party apps",
            ]), runtime: .init(confidence: .high, dryRunSafe: true, opsecScore: 50, tccDomains: ["Automation"], esfExpected: ["OPEN", "EXEC"]))
    }

    private static func screenPlusRemote(state: CollectedState) -> Finding? {
        let signals = state.tcc?.domainSignals ?? []
        let note = state.collectorNotes["tcc.screen_accessibility"] ?? ""
        let screen =
            signals.contains { $0.localizedCaseInsensitiveContains("ScreenCapture=tool_present") }
            || note.localizedCaseInsensitiveContains("screen_recording=tool_present")
            || state.loobins.contains { $0.present && $0.name.lowercased() == "screencapture" }
        let remote =
            state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true
        guard screen && remote else { return nil }

        return Finding(id: "\(id).screen_plus_remote", title: "TCC graph cluster: screen-capture dual-use with remote access posture", severity: .medium, category: .tcc, resolution: .init(evidence: [
                Evidence(type: "screen", detail: "screencapture/tool surface indicated"),
                Evidence(
                    type: "remote",
                    detail:
                        "ssh=\((state.network?.remoteLoginSSH).rootstockDescribe) "
                        + "ard=\((state.network?.screenSharingARD).rootstockDescribe)"
                ),
            ], attackTechniques: ["T1113", "T1021"], remediation: [
                "Review Screen Recording grants; disable unused ARD/SSH",
            ]), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 45, tccDomains: ["ScreenCapture"], esfExpected: ["OPEN", "EXEC"]))
    }

}
