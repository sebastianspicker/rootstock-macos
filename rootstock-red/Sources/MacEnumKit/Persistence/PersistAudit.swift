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
        state.systemLaunchAgents = Self.enumeratePlists(
            at: URL(fileURLWithPath: MacSecurityPaths.systemLaunchAgents, isDirectory: true)
        )
        state.launchDaemons = Self.enumeratePlists(
            at: URL(fileURLWithPath: MacSecurityPaths.systemLaunchDaemons, isDirectory: true)
        )
        state.collectorNotes[Self.id] =
            "user LA=\(state.launchAgents.count); /Library LA=\(state.systemLaunchAgents.count); LD=\(state.launchDaemons.count)"
        return state
    }

    public static func enumerateUserLaunchAgents() -> [LaunchAgentEntry] {
        enumeratePlists(
            at: MacSecurityPaths.userLaunchAgents(home: FileManager.default.homeDirectoryForCurrentUser)
        )
    }

    public static func enumeratePlists(at dir: URL) -> [LaunchAgentEntry] {
        LaunchdPlistFacts.listPlistPaths(in: dir.path)
            .map { path in
                let summary = LaunchdPlistFacts.summarize(plistPath: path)
                return LaunchAgentEntry(
                    label: summary.label,
                    path: path,
                    programArguments: summary.effectiveArguments
                )
            }
            .sorted { $0.path < $1.path }
    }
}
