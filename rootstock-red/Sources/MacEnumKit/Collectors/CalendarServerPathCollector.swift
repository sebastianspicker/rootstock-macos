import Foundation
import RootstockCore

/// Calendar server / CalDAV residual surface (Wave-16).
/// Safety and behavior: path inventory only; never reads calendar event bodies or credentials from CalDAV stores.
public struct CalendarServerPathCollector: Collector {
    public static let id = "collect.calendar_server_path"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = ["Calendar CalDAV residual: path presence only - never reads calendar event bodies or credentials from CalDAV stores"]
        var a: [String] = []
        for path in ["/System/Library/PrivateFrameworks/CalendarDaemon.framework",
            "/System/Library/PrivateFrameworks/CalDAV.framework",
            "/usr/libexec/calaccessd"] where fm.fileExists(atPath: path) {
            a.append(path); notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in [NSHomeDirectory() + "/Library/Calendars",
            NSHomeDirectory() + "/Library/Containers/com.apple.iCal"] where fm.fileExists(atPath: path) {
            b.append(path); notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in [NSHomeDirectory() + "/Library/Preferences/com.apple.iCal.plist",
            "/System/Library/LaunchAgents/com.apple.CalendarAgent.plist"] where fm.fileExists(atPath: path) {
            c.append(path); notes.append("c: \(path)")
        }
        a = Array(Set(a)).sorted(); b = Array(Set(b)).sorted(); c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2
        var state = CollectedState()
        state.calendarServerPath = CalendarServerPathState(
            caldavFrameworkPaths: a, calendarsStorePaths: b, calendarAgentPaths: c,
            caldavSurfacePresent: surface, notes: notes
        )
        state.collectorNotes[Self.id] = "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
