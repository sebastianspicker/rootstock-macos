import Foundation
import RootstockCore

/// Shortcuts iCloud sync residual depth (Wave-16).
/// Safety and behavior: path inventory only; never executes Shortcuts or dumps iCloud-synced automation databases.
public struct ShortcutsIcloudSyncCollector: Collector {
    public static let id = "collect.shortcuts_icloud_sync"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = ["Shortcuts iCloud sync: path presence only - never executes Shortcuts or dumps iCloud-synced automation databases"]
        var a: [String] = []
        for path in ["/System/Applications/Shortcuts.app",
            "/System/Library/PrivateFrameworks/WorkflowKit.framework"] where fm.fileExists(atPath: path) {
            a.append(path); notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in [NSHomeDirectory() + "/Library/Shortcuts",
            NSHomeDirectory() + "/Library/Group Containers/group.is.workflow.my.app"] where fm.fileExists(atPath: path) {
            b.append(path); notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in [NSHomeDirectory() + "/Library/Preferences/com.apple.shortcuts.plist",
            "/System/Library/PrivateFrameworks/VoiceShortcutClient.framework"] where fm.fileExists(atPath: path) {
            c.append(path); notes.append("c: \(path)")
        }
        a = Array(Set(a)).sorted(); b = Array(Set(b)).sorted(); c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2
        var state = CollectedState()
        state.shortcutsIcloudSync = ShortcutsIcloudSyncState(
            shortcutsAppPaths: a, shortcutsDbPaths: b, shortcutsPrefPaths: c,
            shortcutsIcloudSurfacePresent: surface, notes: notes
        )
        state.collectorNotes[Self.id] = "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
