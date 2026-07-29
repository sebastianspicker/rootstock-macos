import Foundation
import RootstockCore

/// Photos.app library collection path plane (Wave-15).
/// Safety and behavior: path inventory only; never reads photo contents or exports Photo Library media.
public struct PhotosLibraryPathCollector: Collector {
    public static let id = "collect.photos_library_path"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = ["Photos library path plane: path presence only - never reads photo contents or exports Photo Library media"]
        var a: [String] = []
        for path in ["/System/Applications/Photos.app",
            "/Applications/Photos.app",
            "/System/Library/PrivateFrameworks/PhotoLibraryServices.framework"] where fm.fileExists(atPath: path) {
            a.append(path); notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in [NSHomeDirectory() + "/Pictures/Photos Library.photoslibrary",
            NSHomeDirectory() + "/Pictures"] where fm.fileExists(atPath: path) {
            b.append(path); notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in [NSHomeDirectory() + "/Library/Containers/com.apple.Photos",
            NSHomeDirectory() + "/Library/Group Containers/group.com.apple.photos"] where fm.fileExists(atPath: path) {
            c.append(path); notes.append("c: \(path)")
        }
        a = Array(Set(a)).sorted(); b = Array(Set(b)).sorted(); c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2
        var state = CollectedState()
        state.photosLibraryPath = PhotosLibraryPathState(
            photosAppPaths: a, photosLibraryPaths: b, photosSupportPaths: c,
            photosSurfacePresent: surface, notes: notes
        )
        state.collectorNotes[Self.id] = "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
