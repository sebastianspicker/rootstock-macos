import Foundation
import RootstockCore

/// Time Machine local snapshot residual depth (Wave-15).
/// Safety and behavior: path inventory only; never mounts snapshots for data theft or deletes backup catalogs.
public struct TmLocalSnapshotDepthCollector: Collector {
    public static let id = "collect.tm_local_snapshot_depth"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = ["TM local snapshot depth: path presence only - never mounts snapshots for data theft or deletes backup catalogs"]
        var a: [String] = []
        for path in ["/usr/bin/tmutil",
            "/System/Library/CoreServices/Time Machine.app",
            "/System/Library/PrivateFrameworks/TimeMachine.framework"] where fm.fileExists(atPath: path) {
            a.append(path); notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in ["/.MobileBackups",
            "/Volumes",
            "/private/var/db/fseventsd"] where fm.fileExists(atPath: path) {
            b.append(path); notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in ["/Library/Preferences/com.apple.TimeMachine.plist",
            NSHomeDirectory() + "/Library/Preferences/com.apple.TimeMachine.plist"] where fm.fileExists(atPath: path) {
            c.append(path); notes.append("c: \(path)")
        }
        a = Array(Set(a)).sorted(); b = Array(Set(b)).sorted(); c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2
        var state = CollectedState()
        state.tmLocalSnapshotDepth = TmLocalSnapshotDepthState(
            tmUtilPaths: a, snapshotStorePaths: b, tmPrefPaths: c,
            tmSnapshotSurfacePresent: surface, notes: notes
        )
        state.collectorNotes[Self.id] = "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
