import Foundation
import RootstockCore

/// Maps / location services residual plane (Wave-16).
/// Safety and behavior: path inventory only; never dumps location history or spoofs CoreLocation positions.
public struct MapsLocationPathCollector: Collector {
    public static let id = "collect.maps_location_path"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = ["Maps location residual: path presence only - never dumps location history or spoofs CoreLocation positions"]
        var a: [String] = []
        for path in ["/System/Applications/Maps.app",
            "/System/Library/Frameworks/CoreLocation.framework",
            "/usr/libexec/locationd"] where fm.fileExists(atPath: path) {
            a.append(path); notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in [NSHomeDirectory() + "/Library/Caches/com.apple.Maps",
            NSHomeDirectory() + "/Library/Containers/com.apple.Maps"] where fm.fileExists(atPath: path) {
            b.append(path); notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in [NSHomeDirectory() + "/Library/Preferences/com.apple.Maps.plist",
            "/System/Library/LaunchDaemons/com.apple.locationd.plist"] where fm.fileExists(atPath: path) {
            c.append(path); notes.append("c: \(path)")
        }
        a = Array(Set(a)).sorted(); b = Array(Set(b)).sorted(); c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2
        var state = CollectedState()
        state.mapsLocationPath = MapsLocationPathState(
            mapsAppPaths: a, mapsCachePaths: b, locationdPaths: c,
            mapsLocationSurfacePresent: surface, notes: notes
        )
        state.collectorNotes[Self.id] = "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
