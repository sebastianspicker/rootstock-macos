import Foundation
import RootstockCore

/// Living-off-the-land execution chain: high-utility bins + quieter planner alternatives.
public struct LOLExecutionChainVector: Check {
    public static let id = "rootstock.vector.lool.execution_chain"
    public static let cost: CollectorCost = .low

    /// Dual-use binaries that commonly form execution / persist chains.
    private static let highUtilityNames: Set<String> = [
        "osascript", "launchctl", "screencapture", "security", "sqlite3", "mdfind",
    ]

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws
        -> [Finding]
    {
        guard Self.shouldFire(state) else { return [] }
        return [Self.finding(for: state)]
    }

    private static func shouldFire(_ state: CollectedState) -> Bool {
        let present = state.loobins.filter(\.present)
        let presentNames = Set(present.map { $0.name.lowercased() })
        let highUtility = present.filter { Self.highUtilityNames.contains($0.name.lowercased()) }
        let hasOsascript = presentNames.contains("osascript")
        let hasLaunchctl = presentNames.contains("launchctl")
        let chainPair = hasOsascript && hasLaunchctl
        let hasHighUtilityCluster = highUtility.count >= 2
        return chainPair || hasHighUtilityCluster
            || (!state.lolPlans.isEmpty && !highUtility.isEmpty)
    }

    private static func finding(for state: CollectedState) -> Finding {
        let present = state.loobins.filter(\.present)
        let presentNames = Set(present.map { $0.name.lowercased() })
        let highUtility = present.filter { Self.highUtilityNames.contains($0.name.lowercased()) }
        let chainPair = presentNames.contains("osascript") && presentNames.contains("launchctl")
        let presentation = Self.presentation(
            chainPair: chainPair, highUtilityCount: highUtility.count)
        return Finding(id: Self.id, title: presentation.title, severity: presentation.severity, category: .lool, resolution: .init(evidence: evidence(
                highUtility: highUtility, plans: state.lolPlans, chainPair: chainPair), attackTechniques: ["T1059.002", "T1059", "T1543.001", "T1218"], remediation: [
                "For authorized discovery, prefer lower-noise planner entries (system_profiler/mdfind/codesign)",
                "Avoid osascript/screencapture without consent - TCC + high ESF noise",
                "Monitor launchctl load/bootstrap and osascript process trees via EDR",
                "OPSEC: chain findings rank quieter LOOBins first; do not default to rainbow dumps",
            ], falsePositiveNotes: "Stock Apple dual-use binaries are expected; finding is chain utility, not malware"), runtime: .init(confidence: .high, dryRunSafe: true, opsecScore: chainPair ? 55 : 35, tccDomains: presentNames.contains("osascript") ? ["Automation"] : [], esfExpected: ["OPEN", "EXEC"]))
    }

    private static func evidence(highUtility: [LOOBinHit], plans: [LOLPlanEntry], chainPair: Bool)
        -> [Evidence]
    {
        chainEvidence(chainPair)
            + highUtilityEvidence(highUtility)
            + plannerEvidence(plans)
            + loudPlanEvidence(plans)
    }

    private static func chainEvidence(_ chainPair: Bool) -> [Evidence] {
        guard chainPair else { return [] }
        return [
            Evidence(
                type: "chain",
                detail: "osascript + launchctl both present - classic execute → persist chain")
        ]
    }

    private static func highUtilityEvidence(_ highUtility: [LOOBinHit]) -> [Evidence] {
        highUtility.prefix(15).map {
            Evidence(
                type: "high_utility_loobin", path: $0.path,
                detail: "\($0.name) tactics=\($0.tactics.joined(separator: ","))")
        }
    }

    private static func plannerEvidence(_ plans: [LOLPlanEntry]) -> [Evidence] {
        let quieter = plans.filter(isRelevantPlannerEntry).sorted { $0.noiseScore < $1.noiseScore }
        guard !quieter.isEmpty else {
            return [
                Evidence(
                    type: "planner",
                    detail: "lolPlans empty - prefer inventory noise heuristics over loud bins")
            ]
        }
        let summary = quieter.prefix(8).map { "\($0.name)@\($0.noiseScore)/\($0.goal)" }.joined(
            separator: ", ")
        let entries = quieter.prefix(10).map {
            Evidence(
                type: "plan_entry", path: $0.path,
                detail: "goal=\($0.goal) noise=\($0.noiseScore) · \($0.rankReason)")
        }
        return [Evidence(type: "quieter_alternatives", detail: "planner quieter-first: \(summary)")]
            + entries
    }

    private static func loudPlanEvidence(_ plans: [LOLPlanEntry]) -> [Evidence] {
        let loudPlans = plans.filter { $0.noiseScore >= 70 }.sorted {
            $0.noiseScore > $1.noiseScore
        }
        guard !loudPlans.isEmpty else { return [] }
        let names = loudPlans.prefix(5).map { "\($0.name)@\($0.noiseScore)" }.joined(
            separator: ", ")
        return [Evidence(type: "loud_bins", detail: "high noise in chain: \(names)")]
    }

    private static func presentation(chainPair: Bool, highUtilityCount: Int) -> (
        severity: Severity, title: String
    ) {
        if chainPair {
            return (
                .medium, "LOL execution chain: osascript + launchctl (prefer quieter planner bins)"
            )
        }
        return (
            .low,
            "LOL high-utility surface (\(highUtilityCount) dual-use bins) with planner alternatives"
        )
    }

    private static func isRelevantPlannerEntry(_ entry: LOLPlanEntry) -> Bool {
        ["discovery", "execute", "persist"].contains(entry.goal)
    }
}
