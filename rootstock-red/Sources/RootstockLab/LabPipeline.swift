import Foundation
import RootstockCore

/// Gates lab actions behind consent and routes lifecycle requests.
public struct LabPipeline: Sendable {
    public var registry: ActionRegistry

    public init(registry: ActionRegistry = .production()) {
        self.registry = registry
    }

    /// Run a single lab action after consent. Uses `LabAction` when available.
    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {
        guard let action = registry.action(id: request.actionId) else {
            throw RootstockError.invalidArgument("Unknown lab action: \(request.actionId)")
        }

        let policy = type(of: action).consent
        try SafetyRails.ensureLabConsent(context: context, policy: policy)

        if let lab = action as? any LabAction {
            return try await lab.run(request: request, context: context)
        }

        // Fallback for non-lifecycle actions (e.g. noop): ignore operation, use Action.run.
        return try await action.run(context: context)
    }

    /// Dry-run plan for all `LabAction` entries (LaunchAgent + dylib surface).
    /// Non-lifecycle actions (e.g. noop with extra confirm token) are skipped so
    /// plan-all works with standard `--i-am-authorized --scope --operator` consent.
    public func planAll(context: EvaluationContext) async throws -> [ActionResult] {
        var planContext = context
        planContext.dryRun = true

        var results: [ActionResult] = []
        for action in registry.actions {
            guard let lab = action as? any LabAction else { continue }
            let id = type(of: lab).id
            let policy = type(of: lab).consent
            try SafetyRails.ensureLabConsent(context: planContext, policy: policy)
            let request = LabActionRequest(actionId: id, operation: .plan)
            results.append(try await lab.run(request: request, context: planContext))
        }
        return results
    }
}

/// JSON-serializable container for multi-action plan output.
public struct LabPlanAllResult: Codable, Sendable, Equatable {
    public var dryRun: Bool
    public var results: [ActionResult]

    public init(dryRun: Bool = true, results: [ActionResult]) {
        self.dryRun = dryRun
        self.results = results
    }
}
