import Foundation
import RootstockCore

/// Reminders cloud path residual plane (Wave-16).
/// Safety and behavior: path inventory only; never reads reminder titles/bodies or exports Reminders databases.
public struct RemindersCloudPathCollector: Collector {
    public static let id = "collect.reminders_cloud_path"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = ["Reminders cloud path: path presence only - never reads reminder titles/bodies or exports Reminders databases"]
        var a: [String] = []
        for path in ["/System/Applications/Reminders.app",
            "/System/Library/PrivateFrameworks/ReminderKit.framework"] where fm.fileExists(atPath: path) {
            a.append(path); notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in [NSHomeDirectory() + "/Library/Reminders",
            NSHomeDirectory() + "/Library/Group Containers/group.com.apple.reminders"] where fm.fileExists(atPath: path) {
            b.append(path); notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in [NSHomeDirectory() + "/Library/Preferences/com.apple.reminders.plist",
            "/System/Library/PrivateFrameworks/RemindersUICore.framework"] where fm.fileExists(atPath: path) {
            c.append(path); notes.append("c: \(path)")
        }
        a = Array(Set(a)).sorted(); b = Array(Set(b)).sorted(); c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2
        var state = CollectedState()
        state.remindersCloudPath = RemindersCloudPathState(
            remindersAppPaths: a, remindersStorePaths: b, remindersPrefPaths: c,
            remindersCloudSurfacePresent: surface, notes: notes
        )
        state.collectorNotes[Self.id] = "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
