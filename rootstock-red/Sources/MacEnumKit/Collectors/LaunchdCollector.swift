import Foundation
import RootstockCore
import MacPersistKit

/// LaunchAgent inventory (user domain) via PersistAudit.
public struct LaunchdCollector: Collector {
    public static let id = "collect.launchd"
    public static let cost: CollectorCost = .medium

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        try await PersistAuditCollector().collect(context: context)
    }
}
