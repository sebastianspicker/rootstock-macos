import Foundation

/// Read-only host state collector.
public protocol Collector: Sendable {
    static var id: String { get }
    static var cost: CollectorCost { get }
    static var requires: [PrivilegeRequirement] { get }
    static var riskClass: RiskClass { get }

    func collect(context: EvaluationContext) async throws -> CollectedState
}

public extension Collector {
    static var cost: CollectorCost { .medium }
    static var requires: [PrivilegeRequirement] { [.user] }
    static var riskClass: RiskClass { .readOnly }
}

/// Pure evaluation of collected state into findings.
public protocol Check: Sendable {
    static var id: String { get }
    static var riskClass: RiskClass { get }
    static var cost: CollectorCost { get }

    func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding]
}

public extension Check {
    static var riskClass: RiskClass { .readOnly }
    static var cost: CollectorCost { .low }
}

/// Result of a gated lab action.
public struct ActionResult: Codable, Sendable, Equatable {
    public var actionId: String
    public var success: Bool
    public var message: String
    public var dryRun: Bool
    public var findings: [Finding]
    /// Ordered plan of what would be / was done.
    public var plannedSteps: [String]
    /// Operator guidance for reversing residual artifacts (BTM, plists, markers).
    public var cleanupNotes: [String]
    /// Paths written or planned for write/remove.
    public var artifacts: [String]

    public init(
        actionId: String,
        success: Bool,
        message: String,
        dryRun: Bool,
        findings: [Finding] = [],
        plannedSteps: [String] = [],
        cleanupNotes: [String] = [],
        artifacts: [String] = []
    ) {
        self.actionId = actionId
        self.success = success
        self.message = message
        self.dryRun = dryRun
        self.findings = findings
        self.plannedSteps = plannedSteps
        self.cleanupNotes = cleanupNotes
        self.artifacts = artifacts
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        actionId = try c.decode(String.self, forKey: .actionId)
        success = try c.decode(Bool.self, forKey: .success)
        message = try c.decode(String.self, forKey: .message)
        dryRun = try c.decode(Bool.self, forKey: .dryRun)
        findings = try c.decodeIfPresent([Finding].self, forKey: .findings) ?? []
        plannedSteps = try c.decodeIfPresent([String].self, forKey: .plannedSteps) ?? []
        cleanupNotes = try c.decodeIfPresent([String].self, forKey: .cleanupNotes) ?? []
        artifacts = try c.decodeIfPresent([String].self, forKey: .artifacts) ?? []
    }
}

/// Mutating / simulation action - never auto-registered into default assess CLI.
public protocol Action: Sendable {
    static var id: String { get }
    static var consent: ConsentPolicy { get }
    static var riskClass: RiskClass { get }

    func run(context: EvaluationContext) async throws -> ActionResult
}

public extension Action {
    static var riskClass: RiskClass { .labOnly }
    static var consent: ConsentPolicy { .labDefault }
}
