import Foundation
import RootstockCore

/// Path-to-impact: ClickFix / paste-and-run Terminal delivery surface.
///
/// Research basis: Microsoft/Jamf ClickFix campaign research (paste-run Terminal/Script Editor).
/// Safety and behavior: typed compound with remote/sensor gap; never builds lures or payloads.
public struct ClickFixTerminalDeliveryVector: Check {
    public static let id = "rootstock.vector.delivery.clickfix_terminal_surface"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        guard shouldReport(state) else { return [] }
        return [Self.finding(for: state, evidence: evidence(for: state))]
    }

    private func shouldReport(_ state: CollectedState) -> Bool {
        let delivery = state.clickFixTerminalDelivery
        let terminal = delivery?.terminalAppPaths.count ?? 0
        let script = delivery?.scriptEditorPaths.count ?? 0
        let loaders = delivery?.loaderBinaryPaths.count ?? 0
        let surface = delivery?.deliverySurfacePresent == true || terminal + script > 0 || loaders >= 2
        return (surface || state.collectorNotes["collect.clickfix_terminal_delivery"] != nil)
            && (loaders >= 1 || terminal >= 1 || script >= 1)
    }

    private func evidence(for state: CollectedState) -> [Evidence] {
        let delivery = state.clickFixTerminalDelivery
        let terminal = delivery?.terminalAppPaths.count ?? 0
        let script = delivery?.scriptEditorPaths.count ?? 0
        let loaders = delivery?.loaderBinaryPaths.count ?? 0
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let sensorThin = state.esf?.clientPaths.isEmpty == true
            || (state.securityProducts.filter(\.present).isEmpty && state.collectorNotes["collect.esf_endpoint_security"] != nil)
        let gkOff = state.protections?.gatekeeperEnabled == false
        var evidence = [Evidence(type: "clickfix_summary", detail: "terminal=\(terminal) scriptEditor=\(script) loaders=\(loaders) remote=\(remote) sensorThin=\(sensorThin) gkOff=\(gkOff)")]
        if let delivery {
            for path in (delivery.terminalAppPaths + delivery.scriptEditorPaths + delivery.loaderBinaryPaths).prefix(12) {
                evidence.append(Evidence(type: "delivery_path", path: path, detail: "paste-run component"))
            }
            for note in delivery.notes.prefix(6) {
                evidence.append(Evidence(type: "delivery_note", detail: note))
            }
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never builds ClickFix lures, never emits paste-this-payload recipes, never weaponizes Terminal/Script Editor delivery."))
        return evidence
    }

    private static func finding(for state: CollectedState, evidence: [Evidence]) -> Finding {
        let delivery = state.clickFixTerminalDelivery
        let loaders = delivery?.loaderBinaryPaths.count ?? 0
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let sensorThin = state.esf?.clientPaths.isEmpty == true
            || (state.securityProducts.filter(\.present).isEmpty && state.collectorNotes["collect.esf_endpoint_security"] != nil)
        let gkOff = state.protections?.gatekeeperEnabled == false
        let severity: Severity = remote && sensorThin ? .high : (remote || gkOff || loaders >= 3 ? .medium : .low)
        return Finding(id: Self.id, title: remote
                ? "ClickFix paste-run delivery surface on remotely reachable host"
                : "ClickFix / paste-and-run Terminal delivery surface", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1204.002", "T1059.004", "T1105"], remediation: [
                "Train users against paste-and-run 'fix' instructions (ClickFix/TerminalFix class)",
                "Prefer managed Terminal paste-warning posture on modern macOS where available",
                "Restrict dual-use loaders via MDM where policy allows; monitor curl|sh process trees",
                "OPSEC: Rootstock Red does not build lures or deliver paste-run payloads",
            ], falsePositiveNotes: "Terminal, shells, and curl ship with macOS. Prioritize hosts with remote access or thin sensor coverage for engagement narrative ranking."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 18, esfExpected: ["OPEN", "EXEC"]))
    }
}
