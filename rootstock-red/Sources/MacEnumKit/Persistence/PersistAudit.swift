import Foundation
import RootstockCore
import RootstockMacFacts

/// Persistence audit (list only). Install/remove lives in RootstockLab (not default).
/// Launchd enumeration uses `LaunchdPlistFacts` (RootstockMacFacts).
public struct PersistAuditCollector: Collector {
    public static let id = "collect.persist_audit"
    public static let cost: CollectorCost = .medium

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        var state = CollectedState()
        state.launchAgents = Self.enumerateUserLaunchAgents()
        state.systemLaunchAgents = LaunchPlistSupport.enumeratePlists(
            in: URL(fileURLWithPath: MacSecurityPaths.systemLaunchAgents, isDirectory: true)
        )
        state.launchDaemons = LaunchPlistSupport.enumeratePlists(
            in: URL(fileURLWithPath: MacSecurityPaths.systemLaunchDaemons, isDirectory: true)
        )
        state.collectorNotes[Self.id] =
            "user LA=\(state.launchAgents.count); /Library LA=\(state.systemLaunchAgents.count); LD=\(state.launchDaemons.count)"
        return state
    }

    public static func enumerateUserLaunchAgents() -> [LaunchAgentEntry] {
        LaunchPlistSupport.enumeratePlists(
            in: MacSecurityPaths.userLaunchAgents(home: FileManager.default.homeDirectoryForCurrentUser)
        )
    }
}
