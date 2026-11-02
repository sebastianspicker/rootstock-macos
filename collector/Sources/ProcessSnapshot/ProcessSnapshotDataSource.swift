import Foundation
import Models
import HostCommand

/// Takes a snapshot of running processes via `ps` and resolves bundle IDs.
public struct ProcessSnapshotDataSource: DataSource {
    public let name = "Process Snapshot"
    public let requiresElevation = false

    /// Known application paths from the scan (set before collect).
    private let knownApps: [Application]

    public init(knownApps: [Application] = []) {
        self.knownApps = knownApps
    }

    public func collect() async -> DataSourceResult {
        guard let output = Shell.run("/bin/ps", ["axo", "pid,ppid,user,comm"]) else {
            return DataSourceResult(
                nodes: [],
                errors: [CollectionError(source: name, message: "Failed to run ps", recoverable: true)]
            )
        }

        let processes = Self.parsePsOutput(output, knownApps: knownApps)
        return DataSourceResult(nodes: processes, errors: [])
    }

    /// Parse `ps axo pid,ppid,user,comm` output (`comm` may contain spaces).
    internal static func parsePsOutput(_ output: String, knownApps: [Application]) -> [RunningProcess] {
        let pathToBundle = BundlePaths.bundleIdMap(knownApps)

        var processes: [RunningProcess] = []

        for line in output.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.hasPrefix("PID") else { continue }

            let parts = trimmed.split(separator: " ", maxSplits: 3, omittingEmptySubsequences: true)
            guard parts.count >= 4, let pid = Int(parts[0]) else { continue }
            let ppid = Int(parts[1])
            let user = String(parts[2])
            let command = parts[3].trimmingCharacters(in: .whitespaces)

            let bundleId = BundlePaths.bundleId(forCommand: command, in: pathToBundle)

            processes.append(RunningProcess(
                pid: pid,
                user: user,
                command: command,
                bundleId: bundleId,
                ppid: ppid
            ))
        }

        return processes
    }
}
