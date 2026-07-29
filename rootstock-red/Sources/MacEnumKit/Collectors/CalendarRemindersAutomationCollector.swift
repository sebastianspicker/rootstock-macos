import Foundation
import RootstockCore

/// Calendar / Reminders automation lateral surface (Wave-13).
///
/// Research basis: public 2025–26 macOS Calendar/Reminders automation tradecraft research.
/// Safety and behavior: typed path inventory only; never reads event contents or creates malicious calendar invites.
public struct CalendarRemindersAutomationCollector: Collector {
    public static let id = "collect.calendar_reminders_automation"
    public static let cost: CollectorCost = .low

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = [
            "Calendar/Reminders automation: path presence only - never reads event contents or creates malicious calendar invites",
        ]
        var a: [String] = []
        for path in ["/System/Applications/Calendar.app",
            "/Applications/Calendar.app",
            NSHomeDirectory() + "/Library/Calendars"] where fm.fileExists(atPath: path) {
            a.append(path)
            notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in ["/System/Applications/Reminders.app",
            NSHomeDirectory() + "/Library/Reminders",
            NSHomeDirectory() + "/Library/Containers/com.apple.reminders"] where fm.fileExists(atPath: path) {
            b.append(path)
            notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in ["/System/Library/Frameworks/EventKit.framework",
            "/System/Library/PrivateFrameworks/CalendarFoundation.framework",
            NSHomeDirectory() + "/Library/Preferences/com.apple.iCal.plist"] where fm.fileExists(atPath: path) {
            c.append(path)
            notes.append("c: \(path)")
        }
        a = Array(Set(a)).sorted()
        b = Array(Set(b)).sorted()
        c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2
        var state = CollectedState()
        state.calendarRemindersAutomation = CalendarRemindersAutomationState(
            calendarAppPaths: a,
            remindersPaths: b,
            eventKitPaths: c,
            automationSurfacePresent: surface,
            notes: notes
        )
        state.collectorNotes[Self.id] =
            "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
