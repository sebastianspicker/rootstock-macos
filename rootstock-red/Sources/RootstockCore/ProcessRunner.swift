import Foundation

/// Intentional injection point for lab-only process execution.
/// Checks and assess collectors must not use this freely.
public struct ProcessRunner: Sendable {
    public var allowed: Bool

    public init(allowed: Bool = false) {
        self.allowed = allowed
    }

    public static func forContext(_ context: EvaluationContext) -> ProcessRunner {
        // Assess mode: never allow shelling out via this runner.
        ProcessRunner(allowed: context.mode == .lab || context.mode == .agent)
    }

    public func run(executable: String, arguments: [String] = []) throws -> String {
        guard allowed else {
            throw RootstockError.processNotAllowedInAssess
        }
        throw RootstockError.invalidArgument(
            "ProcessRunner execution is disabled (refused: \(executable) \(arguments.joined(separator: " ")))"
        )
    }
}
