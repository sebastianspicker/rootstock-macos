import Foundation
import RootstockCore

/// Lifecycle operation for a lab action.
public enum LabOperation: String, Codable, Sendable, CaseIterable, Equatable {
    case install
    case status
    case remove
    case plan
}

/// Request to run a gated lab action with explicit lifecycle operation.
public struct LabActionRequest: Codable, Sendable, Equatable {
    public var actionId: String
    public var operation: LabOperation
    /// Free-form parameters (e.g. `directory`, `label`, `labRoot`, `app`).
    public var parameters: [String: String]

    public init(
        actionId: String,
        operation: LabOperation,
        parameters: [String: String] = [:]
    ) {
        self.actionId = actionId
        self.operation = operation
        self.parameters = parameters
    }
}

/// Lab actions that support install/status/remove/plan lifecycle operations.
public protocol LabAction: Action {
    func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult
}

public extension LabAction {
    /// Default `Action.run` maps to a dry-run `plan` when no request is supplied.
    func run(context: EvaluationContext) async throws -> ActionResult {
        let request = LabActionRequest(actionId: Self.id, operation: .plan)
        return try await run(request: request, context: context)
    }
}
