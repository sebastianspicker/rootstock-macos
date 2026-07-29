import Foundation
import RootstockCore

/// Wave-11 compound: Shortcuts/App Intents × remote / RAE lateral.
public struct ShortcutsLateralCompoundVector: Check {
    public static let id = "rootstock.vector.automation.shortcuts_lateral_compound"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let sa = state.shortcutsAppIntents
        let shortcuts = sa?.shortcutsAppPaths.count ?? 0
        let intents = sa?.appIntentsPaths.count ?? 0
        guard shortcuts >= 1 || intents >= 1 else { return [] }

        let remote =
            state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true
        let rae = state.remoteAppleEvents?.remoteAutomationSurfacePresent == true
            || (state.remoteAppleEvents?.remoteAEPrefPaths.count ?? 0) > 0
        guard remote || rae || shortcuts >= 2 else { return [] }

        var evidence: [Evidence] = [
            Evidence(
                type: "shortcuts_lateral_compound",
                detail: "shortcuts=\(shortcuts) intents=\(intents) remote=\(remote) rae=\(rae)"
            ),
        ]
        if let sa {
            for path in (sa.shortcutsAppPaths + sa.appIntentsPaths).prefix(8) {
                evidence.append(Evidence(type: "automation_compound_path", path: path, detail: "shortcuts×lateral"))
            }
        }
        evidence.append(
            Evidence(type: "honesty", detail: "Never runs Shortcuts or enables Remote Apple Events.")
        )

        let severity: Severity = (remote && rae) ? .high : ((remote || rae) ? .medium : .low)
        return [
            Finding(id: Self.id, title: remote
                    ? "Shortcuts / App Intents × remote lateral compound"
                    : "Shortcuts / App Intents × automation lateral compound", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1059", "T1559", "T1021"], remediation: [
                    "Review Shortcuts that invoke scripting/shell on hosts with remote access",
                    "Disable unused Remote Apple Events; constrain automations via MDM",
                    "OPSEC: path-to-impact ranking only",
                ], falsePositiveNotes: "Shortcuts on laptops with SSH is common for admins; rank unexpected shared automations."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 27, esfExpected: ["OPEN", "EXEC"])),
        ]
    }
}
