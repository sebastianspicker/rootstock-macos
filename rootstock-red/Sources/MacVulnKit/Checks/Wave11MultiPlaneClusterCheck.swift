import Foundation
import RootstockCore

/// Multi-plane Wave-11 compound ranking (URL handlers × launchd overrides × browser extensions × Shortcuts).
///
/// Research basis: engagement narrative across Wave-11 red↔blue pair themes.
/// Safety and behavior: deterministic compounds over CollectedState; not automated exploit orchestration.
public struct Wave11MultiPlaneClusterCheck: Check {
    public static let id = "rootstock.check.vuln.wave11_multi_plane_cluster"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let planes = Self.pairPlanes(state: state)
        guard planes.count >= 2 else { return [] }
        return [Self.compoundFinding(planes: planes, state: state)]
    }

    private static func pairPlanes(state: CollectedState) -> [String] {
        presentPlaneNames([
            .init(name: "url_scheme_handler", isPresent: urlSchemeHandlerPresent(state)),
            .init(name: "launchd_override_depth", isPresent: launchdOverridePresent(state)),
            .init(name: "browser_extension_dualuse", isPresent: browserExtensionPresent(state)),
            .init(name: "shortcuts_app_intents", isPresent: shortcutsAppIntentsPresent(state)),
        ])
    }


    private static func urlSchemeHandlerPresent(_ state: CollectedState) -> Bool {
        let handler = state.urlSchemeHandler
        return handler?.handlerSurfacePresent == true
            || (handler?.launchServicesPaths.count ?? 0) >= 1
            || ((handler?.openerBinaryPaths.count ?? 0) >= 2 && (handler?.urlTypePlistPaths.count ?? 0) >= 1)
    }

    private static func launchdOverridePresent(_ state: CollectedState) -> Bool {
        let override = state.launchdOverrideDepth
        return override?.overrideSurfacePresent == true
            || (override?.overridePlistPaths.count ?? 0) >= 1
            || (override?.securityDisabledHints.count ?? 0) >= 1
    }

    private static func browserExtensionPresent(_ state: CollectedState) -> Bool {
        let browserExtension = state.browserExtensionDualUse
        let total = (browserExtension?.chromiumExtensionPaths.count ?? 0)
            + (browserExtension?.safariExtensionPaths.count ?? 0)
        return browserExtension?.extensionSurfacePresent == true
            || total >= 1
            || (browserExtension?.preferencePaths.count ?? 0) >= 2
    }

    private static func shortcutsAppIntentsPresent(_ state: CollectedState) -> Bool {
        let shortcuts = state.shortcutsAppIntents
        return shortcuts?.automationSurfacePresent == true
            || (shortcuts?.shortcutsAppPaths.count ?? 0) >= 1
            || (shortcuts?.appIntentsPaths.count ?? 0) >= 1
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
        return Finding(
            id: "\(id).multi_plane",
            title: "Wave-11 multi-plane compound: \(sorted.count) planes (\(sorted.joined(separator: ", ")))",
            severity: compoundSeverity(planes: sorted, amplifiers: amps),
            category: .misconfig,
            resolution: .init(
                evidence: compoundEvidence(planes: sorted, amplifiers: amps, state: state),
                attackTechniques: ["T1204", "T1562.001", "T1176", "T1059"],
                remediation: [
                    "Prioritize hosts co-locating launchd-override + browser-extension + remote amplifiers",
                    "Close remote access and restore disabled security products before lower-tier inventory",
                    "Use Wave-11 lab plans under ROE for purple validation of expected telemetry",
                    "OPSEC: treat multi-plane compounds as engagement narrative, not an exploit script",
                ],
                falsePositiveNotes: "Developer workstations may legitimately co-locate many Wave-11 planes. Rank production hosts with remote/FDA/SIP amplifiers first."
            ),
            runtime: .init(confidence: .low, dryRunSafe: true, opsecScore: 28, esfExpected: ["OPEN", "EXEC", "READ", "WRITE"])
        )
    }

    private static func compoundSeverity(planes: [String], amplifiers: [String]) -> Severity {
        if planes.contains("launchd_override_depth") && planes.contains("browser_extension_dualuse") && amplifiers.contains("fda") && amplifiers.contains("remote") { return .high }
        return planes.count >= 3 || (planes.count >= 2 && amplifiers.count >= 2) ? .medium : .low
    }

    private static func compoundEvidence(planes: [String], amplifiers: [String], state: CollectedState) -> [Evidence] {
        let stages = stageLabels(for: planes, amps: amplifiers)
        let amplifierDetail = amplifiers.isEmpty ? "amplifiers=none" : "amplifiers=\(amplifiers.joined(separator: "|")) count=\(amplifiers.count)"
        return [
            Evidence(type: "planes", detail: "planes=\(planes.joined(separator: "|")) count=\(planes.count)"),
            Evidence(type: "amplifiers", detail: amplifierDetail),
            Evidence(type: "stage_labels", detail: "stages=\(stages.joined(separator: "|")) (labels only - not auto-exploit)"),
            Evidence(type: "host", detail: "host=\(state.host?.hostname ?? "unknown") user=\(state.host?.username ?? "unknown")"),
            Evidence(type: "honesty", detail: "Wave-11 multi-plane ranking is path-to-impact narrative for operators. Rootstock Red does not register URL schemes, disable launchd security jobs, dump browser extension secrets, or run Shortcuts/App Intents."),
        ]
    }

    private struct StageRule {
        let label: String
        let planes: Set<String>
        let amplifiers: Set<String>
    }

    private static func stageLabels(for planes: [String], amps: [String]) -> [String] {
        let rules = [
            StageRule(label: "delivery_handler", planes: ["url_scheme_handler"], amplifiers: ["gk_off"]),
            StageRule(label: "defense_evasion", planes: ["launchd_override_depth"], amplifiers: ["sensor_gap"]),
            StageRule(label: "collection_impact", planes: ["browser_extension_dualuse"], amplifiers: ["fda"]),
            StageRule(label: "automation_lateral", planes: ["shortcuts_app_intents"], amplifiers: ["remote"]),
        ]
        let presentPlanes = Set(planes)
        let presentAmplifiers = Set(amps)
        let stages = rules.compactMap { rule in
            !presentPlanes.isDisjoint(with: rule.planes) || !presentAmplifiers.isDisjoint(with: rule.amplifiers)
                ? rule.label
                : nil
        }
        return stages.isEmpty ? ["posture_inventory"] : stages
    }
}
