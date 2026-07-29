import Foundation
import RootstockCore

/// Time Machine / local snapshot data-access surface (path heuristics only).
///
/// Research basis: TM / local-snapshot research as alternate data-access paths (backups often
/// retain deleted secrets); volume-name heuristics.
/// Safety and behavior: typed `TimeMachineState`; never mounts volumes, never reads backup payloads,
/// never invokes `tmutil` restore - binary/prefs presence only.
public struct TimeMachineCollector: Collector {
    public static let id = "collect.time_machine"
    public static let cost: CollectorCost = .low

    private static let preferencePaths: [String] = [
        "/Library/Preferences/com.apple.TimeMachine.plist",
        "/Library/Preferences/com.apple.TimeMachine.MachineID.plist",
    ]

    private static let backupPathCandidates: [String] = [
        "/Volumes/Time Machine Backups",
        "/Volumes/Backups of Macintosh HD",
        "/.MobileBackups",
        "/.MobileBackups.trash",
        "/System/Volumes/Data/.MobileBackups",
    ]

    private static let localSnapshotCandidates: [String] = [
        "/.MobileBackups",
        "/System/Volumes/Data/.MobileBackups",
        "/private/var/db/com.apple.backupd.snapshotstore",
        "/usr/bin/tmutil",
        "/System/Library/CoreServices/backupd.bundle",
        "/System/Library/LaunchDaemons/com.apple.backupd.plist",
        "/System/Library/LaunchDaemons/com.apple.backupd-auto.plist",
    ]

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let probe = Self.probe(fileManager: .default)
        let notes = [
            "Time Machine surface: path presence only - no backup content read, no tmutil restore",
        ] + probe.notes
        return Self.state(from: probe, notes: notes)
    }

    private struct Probe {
        var preferencesPresent: Bool?
        var backupPaths: [String]
        var localSnapshotHints: [String]
        var volumeMountHints: [String]
        var notes: [String]
    }

    private static func probe(fileManager: FileManager) -> Probe {
        var notes: [String] = []
        let preferencesPresent = preferencesPresent(fileManager: fileManager, notes: &notes)
        var backupPaths = existingPaths(
            in: backupPathCandidates,
            notePrefix: "backup_path",
            fileManager: fileManager,
            notes: &notes
        )
        let localSnapshotHints = existingPaths(
            in: localSnapshotCandidates,
            notePrefix: "local_snapshot_hint",
            fileManager: fileManager,
            notes: &notes
        )
        let volumeMountHints = volumeMountHints(
            fileManager: fileManager,
            backupPaths: &backupPaths,
            notes: &notes
        )
        return Probe(
            preferencesPresent: preferencesPresent,
            backupPaths: uniquePaths(backupPaths),
            localSnapshotHints: uniquePaths(localSnapshotHints),
            volumeMountHints: uniquePaths(volumeMountHints),
            notes: notes
        )
    }

    private static func preferencesPresent(fileManager: FileManager, notes: inout [String]) -> Bool? {
        let paths = preferencePaths.filter { fileManager.fileExists(atPath: $0) }
        for path in paths {
            notes.append("TM prefs present: \(path) (not parsing destinations)")
        }
        guard paths.isEmpty else { return true }
        notes.append("Time Machine preference plists not observed at catalog paths")
        return false
    }

    private static func existingPaths(
        in candidates: [String],
        notePrefix: String,
        fileManager: FileManager,
        notes: inout [String]
    ) -> [String] {
        let paths = candidates.filter { fileManager.fileExists(atPath: $0) }
        for path in paths {
            notes.append("\(notePrefix): \(path)")
        }
        return paths
    }

    private static func volumeMountHints(
        fileManager: FileManager,
        backupPaths: inout [String],
        notes: inout [String]
    ) -> [String] {
        let volumesRoot = "/Volumes"
        guard let volumes = try? fileManager.contentsOfDirectory(atPath: volumesRoot) else {
            notes.append("Volumes directory unreadable")
            return []
        }

        let hints = volumes.filter(isTimeMachineVolumeMount).map {
            (volumesRoot as NSString).appendingPathComponent($0)
        }
        for hint in hints {
            notes.append("volume_mount_hint: \(hint)")
            if !backupPaths.contains(hint) {
                backupPaths.append(hint)
            }
        }
        notes.append("Volumes listed count=\(volumes.count) (name filter only)")
        return hints
    }

    private static func isTimeMachineVolumeMount(_ name: String) -> Bool {
        let lowercasedName = name.lowercased()
        return ["backup", "time machine", "timemachine", "tm "].contains {
            lowercasedName.contains($0)
        }
    }

    private static func uniquePaths(_ paths: [String]) -> [String] {
        Array(Set(paths)).sorted()
    }

    private static func state(from probe: Probe, notes: [String]) -> CollectedState {
        var state = CollectedState()
        state.timeMachine = TimeMachineState(
            preferencesPresent: probe.preferencesPresent,
            backupPaths: probe.backupPaths,
            localSnapshotHints: probe.localSnapshotHints,
            volumeMountHints: probe.volumeMountHints,
            notes: notes
        )
        state.collectorNotes[Self.id] =
            "prefs=\(probe.preferencesPresent.map(String.init(describing:)) ?? "nil") "
            + "backups=\(probe.backupPaths.count) "
            + "snapshots=\(probe.localSnapshotHints.count) "
            + "volumes=\(probe.volumeMountHints.count)"
        return state
    }
}
