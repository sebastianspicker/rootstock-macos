import Foundation
import RootstockCore

/// Surfaces ranked LOOBin plans (noise-ascending) for assess purple-team notes.
public struct LOLPlannerCheck: Check {
    public static let id = "rootstock.check.lool.planner"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let plans = state.lolPlans
        guard !plans.isEmpty else { return emptyPlannerFinding(state) }
        return [plannerFinding(plans)]
    }

    private func emptyPlannerFinding(_ state: CollectedState) -> [Finding] {
        guard !state.loobins.isEmpty else { return [] }
        let evidence = [Evidence(type: "note", detail: "loobins=\(state.loobins.count) present=\(state.loobins.filter(\.present).count); no discovery/persist/execute plan rows")]
        return [Finding(id: "\(Self.id).empty", title: "LOL planner produced no ranked entries", severity: .info, category: .lool, resolution: .init(evidence: evidence, attackTechniques: ["T1218"], remediation: ["Expand LOOBin catalog tactics mapping"]), runtime: .init(confidence: .low, dryRunSafe: true, opsecScore: 4))]
    }

    private func plannerFinding(_ plans: [LOLPlanEntry]) -> Finding {
        let quietest = plans.min { $0.noiseScore < $1.noiseScore }
        let loudest = plans.max { $0.noiseScore < $1.noiseScore }
        var techniques = Set(["T1218", "T1059", "T1082"])
        if plans.contains(where: { $0.goal == "persist" }) { techniques.insert("T1543.001") }
        if plans.contains(where: { !$0.tccImpact.isEmpty }) { techniques.insert("T1222") }
        let title = "LOL planner: \(plans.count) ranked entries (quietest \(quietest?.name ?? "?")@\(quietest?.noiseScore ?? 0), loudest \(loudest?.name ?? "?")@\(loudest?.noiseScore ?? 0))"
        return Finding(id: Self.id, title: title, severity: .info, category: .lool, resolution: .init(evidence: plannerEvidence(plans), attackTechniques: techniques.sorted(), remediation: ["Prefer quieter LOOBins for lab discovery (lower noiseScore)", "Avoid high-TCC tools (screencapture / osascript) without consent"], falsePositiveNotes: "Ranking is heuristic; not an execution plan or endorsement"), runtime: .init(confidence: .high, dryRunSafe: true, opsecScore: 6, esfExpected: []))
    }

    private func plannerEvidence(_ plans: [LOLPlanEntry]) -> [Evidence] {
        let grouped = Dictionary(grouping: plans, by: \.goal)
        let goalEvidence = ["discovery", "persist", "execute", "exfil", "download"].compactMap { goal -> Evidence? in
            guard let rows = grouped[goal], !rows.isEmpty else { return nil }
            let summary = rows.sorted { $0.noiseScore < $1.noiseScore }.prefix(5).map { "\($0.name)@\($0.noiseScore)" }.joined(separator: ", ")
            return Evidence(type: "plan_goal", detail: "\(goal): \(summary)")
        }
        return goalEvidence + plans.prefix(25).map { entry in
            let tcc = entry.tccImpact.isEmpty ? "none" : entry.tccImpact.joined(separator: ",")
            return Evidence(type: "plan_entry", path: entry.path, detail: "goal=\(entry.goal) noise=\(entry.noiseScore) tcc=\(tcc) · \(entry.rankReason)")
        }
    }
}
