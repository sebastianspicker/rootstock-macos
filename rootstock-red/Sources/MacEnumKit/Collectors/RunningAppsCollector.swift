import AppKit
import Foundation
import RootstockCore

/// Running applications via NSWorkspace (no `ps`).
public struct RunningAppsCollector: Collector {
    public static let id = "collect.processes"
    public static let cost: CollectorCost = .low

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let apps = NSWorkspace.shared.runningApplications
        let infos = apps.compactMap { app -> RunningAppInfo? in
            guard let name = app.localizedName else { return nil }
            return RunningAppInfo(
                name: name,
                bundleIdentifier: app.bundleIdentifier,
                path: app.bundleURL?.path
            )
        }
        var state = CollectedState()
        state.runningApps = infos
        state.collectorNotes[Self.id] = "NSWorkspace.runningApplications (\(infos.count))"
        return state
    }
}
