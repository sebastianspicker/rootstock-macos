import Foundation
import Models

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
        guard let output = Shell.run("/bin/ps", ["axo", "pid,user,comm"]) else {
            return DataSourceResult(
                nodes: [],
                errors: [CollectionError(source: name, message: "Failed to run ps", recoverable: true)]
            )
        }

        let processes = Self.parsePsOutput(output, knownApps: knownApps)
        return DataSourceResult(nodes: processes, errors: [])
    }

    /// Parse `ps axo pid,user,comm` output.
    internal static func parsePsOutput(_ output: String, knownApps: [Application]) -> [RunningProcess] {
        // Build path → bundleId lookup (only full .app paths — no short names to avoid collisions)
        var pathToBundle: [String: String] = [:]
        for app in knownApps {
            pathToBundle[app.path] = app.bundleId
            let resolvedPath = URL(fileURLWithPath: app.path).resolvingSymlinksInPath().path
            pathToBundle[resolvedPath] = app.bundleId
        }

        var processes: [RunningProcess] = []

        for line in output.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.hasPrefix("PID") else { continue }

            let parts = trimmed.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
            guard parts.count >= 3, let pid = Int(parts[0]) else { continue }
            let user = String(parts[1])
            let command = parts[2].trimmingCharacters(in: .whitespaces)

            // Resolve bundle ID: direct path match or .app/ prefix extraction
            var bundleId = pathToBundle[command]

            if bundleId == nil, let appRange = command.range(of: ".app/") {
                let appPath = String(command[..<appRange.upperBound].dropLast())
                bundleId = pathToBundle[appPath]
            }

            // Only emit processes with a resolved bundle ID (reduces JSON by ~90%)
            guard let resolvedId = bundleId else { continue }

            processes.append(RunningProcess(
                pid: pid,
                user: user,
                command: command,
                bundleId: resolvedId
            ))
        }

        return processes
    }
}
