import Foundation
import RootstockCore
import MacLolKit

/// LOOBins subset inventory + LOLPlanner ranking for common assess goals.
public struct LOOBinsCollector: Collector {
    public static let id = "collect.loobins"
    public static let cost: CollectorCost = .low

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let catalog = (try? LOOBinCatalog.loadEmbedded()) ?? LOOBinCatalog(entries: [])
        var state = CollectedState()
        state.loobins = catalog.inventory()

        // Rank quietest LOOBins for discovery / persist / execute (top 5 each).
        let planner = LOLPlanner(catalog: catalog)
        let goals: [LOLPlanner.Goal] = [.discovery, .persist, .execute]
        let ranked = planner.plan(goals: goals, topN: 5)
        state.lolPlans = ranked.map { $0.asPlanEntry() }

        let planSummary = goals.map { goal in
            let n = ranked.filter { $0.goal == goal }.count
            return "\(goal.rawValue)=\(n)"
        }.joined(separator: " ")
        state.collectorNotes[Self.id] =
            "embedded loobins_subset (\(state.loobins.count) entries); "
            + "lolPlans \(state.lolPlans.count) [\(planSummary)]"
        return state
    }
}
