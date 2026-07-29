import Foundation
import RootstockCore

/// Health app residual path plane (Wave-16).
/// Safety and behavior: path inventory only; never exports HealthKit samples or medical records.
public struct HealthPathPlaneCollector: Collector {
    public static let id = "collect.health_path_plane"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = ["Health path plane: path presence only - never exports HealthKit samples or medical records"]
        var a: [String] = []
        for path in ["/System/Applications/Health.app",
            "/System/Library/Frameworks/HealthKit.framework",
            "/usr/libexec/healthd"] where fm.fileExists(atPath: path) {
            a.append(path); notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in [NSHomeDirectory() + "/Library/Health",
            NSHomeDirectory() + "/Library/Containers/com.apple.Health"] where fm.fileExists(atPath: path) {
            b.append(path); notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in [NSHomeDirectory() + "/Library/Preferences/com.apple.Health.plist",
            "/System/Library/PrivateFrameworks/HealthDaemon.framework"] where fm.fileExists(atPath: path) {
            c.append(path); notes.append("c: \(path)")
        }
        a = Array(Set(a)).sorted(); b = Array(Set(b)).sorted(); c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2
        var state = CollectedState()
        state.healthPathPlane = HealthPathPlaneState(
            healthAppPaths: a, healthStorePaths: b, healthdPaths: c,
            healthSurfacePresent: surface, notes: notes
        )
        state.collectorNotes[Self.id] = "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
