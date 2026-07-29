import Foundation
import RootstockCore

/// Path-to-impact: AppleScript/Automation / AppleEvents execution surface (TCC-honest).
///
/// Research basis: LOOBins osascript, PersistentJXA, Empire OSX scripting modules.
/// Safety and behavior: ranks quieter planner alternatives; never claims silent Automation; no JXA runtime.
public struct AutomationExecutionSurfaceVector: Check {
    public static let id = "rootstock.vector.tcc.automation_execution_surface"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        guard let finding = automationFinding(for: state) else { return [] }
        return [finding]
    }

private func hasAutomationSurface(_ state: CollectedState) -> Bool {
        if state.loobins.contains(where: { $0.present && $0.name.lowercased() == "osascript" }) {
            return true
        }
        return state.lolPlans.contains { plan in
            plan.tccImpact.contains { $0.localizedCaseInsensitiveContains("automation") }
                || plan.name.lowercased() == "osascript"
                || plan.goal == "execute"
        }
    }

    private func isLoudAutomationSurface(_ state: CollectedState) -> Bool {
        state.lolPlans.contains { $0.noiseScore >= 70 || $0.name.lowercased() == "osascript" }
    }

    private func automationTitle(_ state: CollectedState, loud: Bool) -> String {
        let hasOsascript = state.loobins.contains { $0.present && $0.name.lowercased() == "osascript" }
        return hasOsascript && loud
            ? "Automation execution surface: osascript present (high user-prompt / TCC risk)"
            : "Automation / AppleEvents execution surface with planner alternatives"
    }

private func automationFinding(for state: CollectedState) -> Finding? {
        guard hasAutomationSurface(state) else { return nil }
        let loud = isLoudAutomationSurface(state)
        return Self.finding(
            evidence: automationEvidence(state),
            title: automationTitle(state, loud: loud),
            loud: loud
        )
    }

    private func automationEvidence(_ state: CollectedState) -> [Evidence] {
        let osa = state.loobins.first { $0.present && $0.name.lowercased() == "osascript" }
        let autoPlans = state.lolPlans.filter {
            $0.tccImpact.contains { $0.localizedCaseInsensitiveContains("automation") }
                || $0.name.lowercased() == "osascript"
                || $0.goal == "execute"
        }
        var evidence = [Evidence(
            type: "summary",
            detail: "osascriptPresent=\(osa != nil) automationTaggedPlans=\(autoPlans.filter { !$0.tccImpact.isEmpty }.count) executePlans=\(autoPlans.filter { $0.goal == "execute" }.count)"
        )]
        if let osa {
            evidence.append(Evidence(
                type: "loobin",
                path: osa.path,
                detail: "osascript tactics=\(osa.tactics.joined(separator: ","))"
            ))
        }
        let quieter = state.lolPlans
            .filter { $0.goal == "execute" || $0.goal == "discovery" }
            .sorted { $0.noiseScore < $1.noiseScore }
        for entry in quieter.prefix(8) {
            evidence.append(Evidence(
                type: "planner_alt",
                path: entry.path,
                detail: "\(entry.name) noise=\(entry.noiseScore) tcc=\(entry.tccImpact.joined(separator: ",")) · \(entry.rankReason)"
            ))
        }
        evidence.append(Evidence(
            type: "tcc_honesty",
            detail: "Automation/AppleEvents often prompts the user on modern macOS - silent JXA execution claims are false without prior TCC grants"
        ))
        return evidence
    }

    private static func finding(evidence: [Evidence], title: String, loud: Bool) -> Finding {
        Finding(id: Self.id, title: title, severity: loud ? .medium : .low, category: .tcc, resolution: .init(evidence: evidence, attackTechniques: ["T1059.002", "T1059", "T1559"], remediation: [
                "Prefer quieter LOOBin planner entries over osascript for authorized discovery",
                "Review Automation TCC grants in System Settings → Privacy & Security",
                "Monitor osascript process trees and AppleEvents via EDR/ESF",
                "OPSEC: Automation is user-visible noise - Rootstock Red does not run JXA payloads in assess",
            ], falsePositiveNotes: "osascript ships with macOS; presence is expected. Finding is dual-use ranking, not malware."), runtime: .init(confidence: .high, dryRunSafe: true, opsecScore: loud ? 60 : 35, tccDomains: ["Automation"], esfExpected: ["OPEN", "EXEC", "USER_PROMPT"]))
    }
}
