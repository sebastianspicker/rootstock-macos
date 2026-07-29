import Foundation
import RootstockCore

/// Podcasts library path residual (Wave-16).
/// Safety and behavior: path inventory only; never dumps podcast episode files or account tokens.
public struct PodcastsPathPlaneCollector: Collector {
    public static let id = "collect.podcasts_path_plane"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = ["Podcasts path plane: path presence only - never dumps podcast episode files or account tokens"]
        var a: [String] = []
        for path in ["/System/Applications/Podcasts.app",
            "/System/Library/PrivateFrameworks/PodcastsFoundation.framework"] where fm.fileExists(atPath: path) {
            a.append(path); notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in [NSHomeDirectory() + "/Library/Group Containers/243LU875E5.groups.com.apple.podcasts",
            NSHomeDirectory() + "/Library/Containers/com.apple.podcasts"] where fm.fileExists(atPath: path) {
            b.append(path); notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in [NSHomeDirectory() + "/Library/Preferences/com.apple.podcasts.plist",
            "/System/Library/PrivateFrameworks/PodcastsKit.framework"] where fm.fileExists(atPath: path) {
            c.append(path); notes.append("c: \(path)")
        }
        a = Array(Set(a)).sorted(); b = Array(Set(b)).sorted(); c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2
        var state = CollectedState()
        state.podcastsPathPlane = PodcastsPathPlaneState(
            podcastsAppPaths: a, podcastsStorePaths: b, podcastsPrefPaths: c,
            podcastsSurfacePresent: surface, notes: notes
        )
        state.collectorNotes[Self.id] = "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
