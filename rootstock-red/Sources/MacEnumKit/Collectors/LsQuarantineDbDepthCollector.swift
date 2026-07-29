import Foundation
import RootstockCore

/// LaunchServices QuarantineEvents DB residual depth (Wave-14).
/// Research basis: 2025–26 macOS LS QuarantineEvents depth tradecraft.
/// Safety and behavior: path inventory only; never deletes QuarantineEvents rows or clears LS quarantine history.
public struct LsQuarantineDbDepthCollector: Collector {
    public static let id = "collect.ls_quarantine_db_depth"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = ["LS QuarantineEvents depth: path presence only - never deletes QuarantineEvents rows or clears LS quarantine history"]
        var a: [String] = []
        for path in [NSHomeDirectory() + "/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2",
            NSHomeDirectory() + "/Library/Preferences/com.apple.LaunchServices"] where fm.fileExists(atPath: path) {
            a.append(path); notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in ["/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework",
            "/System/Library/PrivateFrameworks/Quarantine.framework"] where fm.fileExists(atPath: path) {
            b.append(path); notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in ["/usr/bin/xattr",
            "/usr/bin/sqlite3",
            NSHomeDirectory() + "/Downloads"] where fm.fileExists(atPath: path) {
            c.append(path); notes.append("c: \(path)")
        }
        a = Array(Set(a)).sorted(); b = Array(Set(b)).sorted(); c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2
        var state = CollectedState()
        state.lsQuarantineDbDepth = LsQuarantineDbDepthState(
            quarantineDbPaths: a, lsSupportPaths: b, quarantineToolHints: c,
            quarantineDbSurfacePresent: surface, notes: notes
        )
        state.collectorNotes[Self.id] = "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
