import Foundation
import RootstockCore

/// HomeKit residual path plane (Wave-16).
/// Safety and behavior: path inventory only; never enumerates HomeKit accessory secrets or pairs devices.
public struct HomekitPathPlaneCollector: Collector {
    public static let id = "collect.homekit_path_plane"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = ["HomeKit path plane: path presence only - never enumerates HomeKit accessory secrets or pairs devices"]
        var a: [String] = []
        for path in ["/System/Applications/Home.app",
            "/System/Library/Frameworks/HomeKit.framework",
            "/usr/libexec/homed"] where fm.fileExists(atPath: path) {
            a.append(path); notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in [NSHomeDirectory() + "/Library/HomeKit",
            NSHomeDirectory() + "/Library/Group Containers/group.com.apple.home"] where fm.fileExists(atPath: path) {
            b.append(path); notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in [NSHomeDirectory() + "/Library/Preferences/com.apple.Home.plist",
            "/System/Library/LaunchDaemons/com.apple.homed.plist"] where fm.fileExists(atPath: path) {
            c.append(path); notes.append("c: \(path)")
        }
        a = Array(Set(a)).sorted(); b = Array(Set(b)).sorted(); c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2
        var state = CollectedState()
        state.homekitPathPlane = HomekitPathPlaneState(
            homeAppPaths: a, homeKitStorePaths: b, homedPaths: c,
            homekitSurfacePresent: surface, notes: notes
        )
        state.collectorNotes[Self.id] = "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
