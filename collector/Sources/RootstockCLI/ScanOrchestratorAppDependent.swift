import Foundation
import Models
import Persistence
import ProcessSnapshot

extension ScanOrchestrator {
    /// Persistence runs after application discovery so it can scan the launchd jobs and
    /// login items embedded in the discovered application bundles.
    func collectLaunchItems(
        config: ModuleConfig,
        applications: [Application],
        errors: inout [CollectionError]
    ) async -> [LaunchItem] {
        guard config.includes(.persistence) else { return [] }
        let timedResult = await timed {
            await PersistenceDataSource(knownApps: applications).collect()
        }
        return collectNodes(timedResult, as: LaunchItem.self, label: "Persistence", noun: "items", errors: &errors)
    }

    func collectRunningProcesses(
        config: ModuleConfig,
        applications: [Application],
        errors: inout [CollectionError]
    ) async -> [RunningProcess] {
        guard config.includes(.processSnapshot) else { return [] }
        let (result, elapsed) = await timed {
            await ProcessSnapshotDataSource(knownApps: applications).collect()
        }
        let runningProcesses = result.nodes.compactMap { $0 as? RunningProcess }
        errors.append(contentsOf: result.errors)
        if verbose {
            err("  [Processes]    completed in \(format(elapsed))  (\(runningProcesses.count) processes, \(result.errors.count) errors)")
        }
        return runningProcesses
    }
}
