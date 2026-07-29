import Foundation
import RootstockCore

/// TV.app residual path plane (Wave-16).
/// Safety and behavior: path inventory only; never dumps TV.app media caches or account material.
public struct TvAppPathPlaneCollector: Collector {
    public static let id = "collect.tv_app_path_plane"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = ["TV.app path plane: path presence only - never dumps TV.app media caches or account material"]
        var a: [String] = []
        for path in ["/System/Applications/TV.app",
            "/System/Library/PrivateFrameworks/TVPlayback.framework"] where fm.fileExists(atPath: path) {
            a.append(path); notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in [NSHomeDirectory() + "/Library/Containers/com.apple.TV",
            NSHomeDirectory() + "/Library/Group Containers/group.com.apple.tv"] where fm.fileExists(atPath: path) {
            b.append(path); notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in [NSHomeDirectory() + "/Library/Preferences/com.apple.TV.plist",
            "/System/Library/PrivateFrameworks/VideosUI.framework"] where fm.fileExists(atPath: path) {
            c.append(path); notes.append("c: \(path)")
        }
        a = Array(Set(a)).sorted(); b = Array(Set(b)).sorted(); c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2
        var state = CollectedState()
        state.tvAppPathPlane = TvAppPathPlaneState(
            tvAppPaths: a, tvContainerPaths: b, tvPrefPaths: c,
            tvSurfacePresent: surface, notes: notes
        )
        state.collectorNotes[Self.id] = "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
