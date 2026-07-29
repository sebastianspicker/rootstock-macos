import Foundation
import RootstockCore

/// Path-to-impact: browser extension dual-use persistence / collection plane.
///
/// Research basis: broad-permission extension persistence (2025–26 browser malware).
/// Safety and behavior: multi-browser path plane + FDA/remote; never dumps extension secrets.
public struct BrowserExtensionDualUseVector: Check {
    public static let id = "rootstock.vector.persist.browser_extension_dualuse"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        guard shouldReport(state) else { return [] }
        return [Self.finding(for: state, evidence: evidence(for: state))]
    }

private func shouldReport(_ state: CollectedState) -> Bool {
        let extensions = state.browserExtensionDualUse
        let total = (extensions?.chromiumExtensionPaths.count ?? 0) + (extensions?.safariExtensionPaths.count ?? 0)
        let prefs = extensions?.preferencePaths.count ?? 0
        let surface = extensions?.extensionSurfacePresent == true || total >= 1 || prefs >= 2
        return (surface || state.collectorNotes["collect.browser_extension_dualuse"] != nil)
            && (total >= 1 || prefs >= 2)
    }

    private func evidence(for state: CollectedState) -> [Evidence] {
        let extensions = state.browserExtensionDualUse
        let chromium = extensions?.chromiumExtensionPaths.count ?? 0
        let safari = extensions?.safariExtensionPaths.count ?? 0
        let prefs = extensions?.preferencePaths.count ?? 0
        let fda = state.tcc?.fullDiskAccessLikely == true
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        var evidence = [Evidence(
            type: "browser_extension_summary",
            detail: "chromium=\(chromium) safari=\(safari) prefs=\(prefs) fda=\(fda) remote=\(remote)"
        )]
        if let extensions {
            for path in (extensions.chromiumExtensionPaths + extensions.safariExtensionPaths + extensions.preferencePaths).prefix(12) {
                evidence.append(Evidence(type: "extension_path", path: path, detail: "extension dual-use path (meta only)"))
            }
            for note in extensions.notes.prefix(6) {
                evidence.append(Evidence(type: "extension_note", detail: note))
            }
        }
        evidence.append(Evidence(
            type: "honesty",
            detail: "Assess never dumps extension storage, cookies, tokens, or passwords from browser profiles."
        ))
        return evidence
    }

    private static func finding(for state: CollectedState, evidence: [Evidence]) -> Finding {
        let extensions = state.browserExtensionDualUse
        let chromium = extensions?.chromiumExtensionPaths.count ?? 0
        let safari = extensions?.safariExtensionPaths.count ?? 0
        let total = chromium + safari
        let fda = state.tcc?.fullDiskAccessLikely == true
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let severity: Severity = fda && total >= 2 && remote
            ? .high
            : (fda || (chromium >= 1 && safari >= 1) || total >= 2 ? .medium : .low)
        return Finding(id: Self.id, title: fda
                ? "Browser extension dual-use plane under likely Full Disk Access"
                : "Browser extension dual-use persistence / collection plane", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1176", "T1555.003", "T1005"], remediation: [
                "Inventory browser extensions via MDM/EDR; remove unapproved extensions",
                "Restrict enterprise extension allowlists; monitor broad host/permission grants",
                "Correlate extension install times with phishing delivery",
                "OPSEC: Rootstock Red does not dump extension secrets or cookies",
            ], falsePositiveNotes: "Enterprise browsers often ship approved extensions. Elevate multi-browser roots under FDA/remote."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 26, esfExpected: ["OPEN", "READ"]))
    }
}
