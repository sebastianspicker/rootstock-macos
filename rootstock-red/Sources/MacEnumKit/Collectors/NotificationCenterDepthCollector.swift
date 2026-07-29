import Foundation
import RootstockCore

/// Notification Center residual depth (Wave-16).
/// Safety and behavior: path inventory only; never dumps notification body contents or forges notification payloads.
public struct NotificationCenterDepthCollector: Collector {
    public static let id = "collect.notification_center_depth"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = ["Notification Center depth: path presence only - never dumps notification body contents or forges notification payloads"]
        var a: [String] = []
        for path in ["/System/Library/PrivateFrameworks/UserNotifications.framework",
            "/System/Library/CoreServices/NotificationCenter.app",
            "/usr/sbin/usernoted"] where fm.fileExists(atPath: path) {
            a.append(path); notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in [NSHomeDirectory() + "/Library/Application Support/NotificationCenter",
            NSHomeDirectory() + "/Library/Group Containers/group.com.apple.usernoted"] where fm.fileExists(atPath: path) {
            b.append(path); notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in [NSHomeDirectory() + "/Library/Preferences/com.apple.ncprefs.plist",
            "/System/Library/LaunchAgents/com.apple.usernoted.plist"] where fm.fileExists(atPath: path) {
            c.append(path); notes.append("c: \(path)")
        }
        a = Array(Set(a)).sorted(); b = Array(Set(b)).sorted(); c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2
        var state = CollectedState()
        state.notificationCenterDepth = NotificationCenterDepthState(
            notificationFrameworkPaths: a, notificationStorePaths: b, notificationPrefPaths: c,
            notificationSurfacePresent: surface, notes: notes
        )
        state.collectorNotes[Self.id] = "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
