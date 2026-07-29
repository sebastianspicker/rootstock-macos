import Foundation
import RootstockCore

/// Music / media library path residual (Wave-16).
/// Safety and behavior: path inventory only; never exports Music library media or DRM material.
public struct MusicLibraryPathCollector: Collector {
    public static let id = "collect.music_library_path"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = ["Music library path: path presence only - never exports Music library media or DRM material"]
        var a: [String] = []
        for path in ["/System/Applications/Music.app",
            "/System/Library/PrivateFrameworks/iTunesCloud.framework",
            "/System/Library/Frameworks/MediaPlayer.framework"] where fm.fileExists(atPath: path) {
            a.append(path); notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in [NSHomeDirectory() + "/Music/Music",
            NSHomeDirectory() + "/Music/iTunes",
            NSHomeDirectory() + "/Library/Containers/com.apple.Music"] where fm.fileExists(atPath: path) {
            b.append(path); notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in [NSHomeDirectory() + "/Library/Preferences/com.apple.Music.plist",
            "/System/Library/PrivateFrameworks/MediaLibrary.framework"] where fm.fileExists(atPath: path) {
            c.append(path); notes.append("c: \(path)")
        }
        a = Array(Set(a)).sorted(); b = Array(Set(b)).sorted(); c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2
        var state = CollectedState()
        state.musicLibraryPath = MusicLibraryPathState(
            musicAppPaths: a, musicLibraryPaths: b, musicPrefPaths: c,
            musicSurfacePresent: surface, notes: notes
        )
        state.collectorNotes[Self.id] = "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
