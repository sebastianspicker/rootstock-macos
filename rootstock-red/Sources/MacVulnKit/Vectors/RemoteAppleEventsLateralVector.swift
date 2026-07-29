import Foundation
import RootstockCore

/// Path-to-impact: Remote Apple Events / EPPC Automation lateral posture.
///
/// Research basis: Remote AE / ARD lateral checklists; EPPC historical surface.
/// Safety and behavior: distinct from local osascript dual-use; never enables RAE or sends AE.
public struct RemoteAppleEventsLateralVector: Check {
    public static let id = "rootstock.vector.automation.remote_apple_events_lateral"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        guard shouldReport(state) else { return [] }
        return [Self.finding(for: state, evidence: evidence(for: state))]
    }

    private func shouldReport(_ state: CollectedState) -> Bool {
        hasSurface(state) && hasImpact(state)
    }

    private func hasSurface(_ state: CollectedState) -> Bool {
        let rae = state.remoteAppleEvents
        let prefs = rae?.remoteAEPrefPaths.count ?? 0
        let eppc = rae?.eppcFrameworkPaths.count ?? 0
        let remoteMgmt = rae?.remoteMgmtHints.count ?? 0
        let surface = rae?.remoteAutomationSurfacePresent == true || prefs + eppc + remoteMgmt > 0
        let note = state.collectorNotes["collect.remote_apple_events"] != nil

        return surface || note
    }

    private func hasImpact(_ state: CollectedState) -> Bool {
        let rae = state.remoteAppleEvents
        let prefs = rae?.remoteAEPrefPaths.count ?? 0
        let eppc = rae?.eppcFrameworkPaths.count ?? 0
        let remoteMgmt = rae?.remoteMgmtHints.count ?? 0
        let ssh = state.network?.remoteLoginSSH == true
        let ard = state.network?.screenSharingARD == true
        return ssh || ard || prefs >= 1 || eppc >= 2 || remoteMgmt >= 2
    }

    private func evidence(for state: CollectedState) -> [Evidence] {
        let rae = state.remoteAppleEvents
        let prefs = rae?.remoteAEPrefPaths.count ?? 0
        let eppc = rae?.eppcFrameworkPaths.count ?? 0
        let remoteMgmt = rae?.remoteMgmtHints.count ?? 0
        let ssh = state.network?.remoteLoginSSH == true
        let ard = state.network?.screenSharingARD == true
        let localAuto = state.loobins.contains { $0.present && $0.name.lowercased() == "osascript" }
        var evidence: [Evidence] = [
            Evidence(
                type: "rae_summary",
                detail:
                    "prefs=\(prefs) eppc=\(eppc) remoteMgmt=\(remoteMgmt) "
                    + "ssh=\(ssh) ard=\(ard) osascript=\(localAuto)"
            ),
        ]
        if let rae {
            for path in (rae.remoteAEPrefPaths + rae.eppcFrameworkPaths + rae.remoteMgmtHints).prefix(12) {
                evidence.append(Evidence(type: "rae_path", path: path, detail: "remote automation component"))
            }
            for n in rae.notes.prefix(6) {
                evidence.append(Evidence(type: "rae_note", detail: n))
            }
        }
        evidence.append(
            Evidence(
                type: "honesty",
                detail:
                    "Assess never enables Remote Apple Events, never sends remote AppleEvents, "
                    + "never weaponizes EPPC/Automation lateral movement."
            )
        )

        return evidence
    }

    private static func finding(for state: CollectedState, evidence: [Evidence]) -> Finding {
        let rae = state.remoteAppleEvents
        let prefs = rae?.remoteAEPrefPaths.count ?? 0
        let ssh = state.network?.remoteLoginSSH == true
        let ard = state.network?.screenSharingARD == true
        let severity: Severity
        if (ssh || ard) && prefs >= 1 {
            severity = .medium
        } else if ssh || ard {
            severity = .low
        } else {
            severity = .info
        }

        return Finding(id: Self.id, title: (ssh || ard)
                    ? "Remote Apple Events / EPPC lateral surface with remote access enabled"
                    : "Remote Apple Events / EPPC automation lateral posture surface", severity: severity, category: .network, resolution: .init(evidence: evidence, attackTechniques: ["T1021", "T1059.002", "T1559.002"], remediation: [
                    "Disable Remote Apple Events unless required; manage via MDM Sharing policies",
                    "Restrict Screen Sharing / ARD and require strong authentication",
                    "Monitor AEServer / osascript process trees over the network via EDR",
                    "OPSEC: Rootstock Red does not send remote AppleEvents or enable RAE",
                ], falsePositiveNotes: "AppleScript frameworks are stock on macOS. Prioritize hosts with remote login "
                    + "or ARD enabled when ranking lateral impact."), runtime: .init(confidence: .low, dryRunSafe: true, opsecScore: 25, tccDomains: ["Automation"], esfExpected: ["OPEN"]))
    }
}
