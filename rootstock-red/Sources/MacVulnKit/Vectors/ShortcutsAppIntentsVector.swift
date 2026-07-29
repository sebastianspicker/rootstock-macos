import Foundation
import RootstockCore

/// Path-to-impact: Shortcuts / App Intents automation lateral surface.
///
/// Research basis: Shortcuts automation / App Intents 2024–26 execution research.
/// Safety and behavior: automation path compounds with remote/TCC; never runs shortcuts.
public struct ShortcutsAppIntentsVector: Check {
    public static let id = "rootstock.vector.automation.shortcuts_app_intents"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        guard hasSurface(state), hasInventory(state) else { return [] }
        return [Self.finding(for: state, evidence: evidence(for: state))]
    }

    private func hasSurface(_ state: CollectedState) -> Bool {
        let sa = state.shortcutsAppIntents
        let shortcuts = sa?.shortcutsAppPaths.count ?? 0
        let intents = sa?.appIntentsPaths.count ?? 0
        let surface = sa?.automationSurfacePresent == true || shortcuts + intents >= 1
        let note = state.collectorNotes["collect.shortcuts_app_intents"] != nil
        return surface || note
    }

    private func hasInventory(_ state: CollectedState) -> Bool {
        let sa = state.shortcutsAppIntents
        return (sa?.shortcutsAppPaths.count ?? 0) >= 1 || (sa?.appIntentsPaths.count ?? 0) >= 1
    }

    private func evidence(for state: CollectedState) -> [Evidence] {
        let sa = state.shortcutsAppIntents
        let shortcuts = sa?.shortcutsAppPaths.count ?? 0
        let intents = sa?.appIntentsPaths.count ?? 0
        let prefs = sa?.automationPrefPaths.count ?? 0
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let rae = state.remoteAppleEvents?.remoteAutomationSurfacePresent == true
        let fda = state.tcc?.fullDiskAccessLikely == true

        var evidence: [Evidence] = [
            Evidence(
                type: "shortcuts_intents_summary",
                detail:
                    "shortcuts=\(shortcuts) intents=\(intents) prefs=\(prefs) "
                    + "remote=\(remote) rae=\(rae) fda=\(fda)"
            ),
        ]
        if let sa {
            for path in (sa.shortcutsAppPaths + sa.appIntentsPaths + sa.automationPrefPaths).prefix(12) {
                evidence.append(Evidence(type: "automation_path", path: path, detail: "Shortcuts/App Intents path"))
            }
            for n in sa.notes.prefix(6) {
                evidence.append(Evidence(type: "automation_note", detail: n))
            }
        }
        evidence.append(
            Evidence(
                type: "honesty",
                detail:
                    "Assess never runs Shortcuts, never forges App Intents, and never enables personal automations."
            )
        )

        return evidence
    }

    private static func finding(for state: CollectedState, evidence: [Evidence]) -> Finding {
        let shortcuts = state.shortcutsAppIntents?.shortcutsAppPaths.count ?? 0
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let rae = state.remoteAppleEvents?.remoteAutomationSurfacePresent == true
        let fda = state.tcc?.fullDiskAccessLikely == true
        let severity: Severity
        if remote && (rae || fda) && shortcuts >= 2 {
            severity = .high
        } else if remote || rae || shortcuts >= 2 {
            severity = .medium
        } else {
            severity = .low
        }

        return Finding(id: Self.id, title: remote
                    ? "Shortcuts / App Intents automation surface with remote amplifier"
                    : "Shortcuts / App Intents automation lateral surface", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1059", "T1546", "T1559"], remediation: [
                    "Review personal automations and shared Shortcuts for untrusted actions",
                    "Restrict Shortcuts network/scripting actions via MDM where available",
                    "Correlate Shortcuts database changes with phishing delivery timelines",
                    "OPSEC: Rootstock Red does not execute Shortcuts or forge App Intents",
                ], falsePositiveNotes: "Shortcuts.app ships on modern macOS. Elevate when automation co-presents with remote access or RAE."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "EXEC"]))
    }
}
