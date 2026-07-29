import Foundation
import RootstockCore

/// Find My residual path plane (Wave-16).
/// Safety and behavior: path inventory only; never queries Find My device locations or dumps owner tokens.
public struct FindmyPathPlaneCollector: Collector {
    public static let id = "collect.findmy_path_plane"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = ["Find My path plane: path presence only - never queries Find My device locations or dumps owner tokens"]
        var a: [String] = []
        for path in ["/System/Applications/FindMy.app",
            "/System/Library/PrivateFrameworks/FindMyDevice.framework",
            "/usr/libexec/fmfd"] where fm.fileExists(atPath: path) {
            a.append(path); notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in [NSHomeDirectory() + "/Library/Caches/com.apple.findmy",
            NSHomeDirectory() + "/Library/Containers/com.apple.findmy"] where fm.fileExists(atPath: path) {
            b.append(path); notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in [NSHomeDirectory() + "/Library/Preferences/com.apple.FindMy.plist",
            "/System/Library/LaunchDaemons/com.apple.fmfd.plist"] where fm.fileExists(atPath: path) {
            c.append(path); notes.append("c: \(path)")
        }
        a = Array(Set(a)).sorted(); b = Array(Set(b)).sorted(); c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2
        var state = CollectedState()
        state.findmyPathPlane = FindmyPathPlaneState(
            findMyAppPaths: a, findMyCachePaths: b, fmfdPaths: c,
            findmySurfacePresent: surface, notes: notes
        )
        state.collectorNotes[Self.id] = "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
