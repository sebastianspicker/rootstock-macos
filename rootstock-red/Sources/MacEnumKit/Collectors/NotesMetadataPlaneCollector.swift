import Foundation
import RootstockCore

/// Notes.app metadata collection path plane (Wave-14).
/// Research basis: 2025–26 macOS Notes metadata plane tradecraft.
/// Safety and behavior: path inventory only; never reads Notes body contents or exports note secrets.
public struct NotesMetadataPlaneCollector: Collector {
    public static let id = "collect.notes_metadata_plane"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = ["Notes metadata plane: path presence only - never reads Notes body contents or exports note secrets"]
        var a: [String] = []
        for path in ["/System/Applications/Notes.app",
            "/Applications/Notes.app",
            "/System/Library/PrivateFrameworks/NotesShared.framework"] where fm.fileExists(atPath: path) {
            a.append(path); notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in [NSHomeDirectory() + "/Library/Group Containers/group.com.apple.notes",
            NSHomeDirectory() + "/Library/Containers/com.apple.Notes"] where fm.fileExists(atPath: path) {
            b.append(path); notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in [NSHomeDirectory() + "/Library/Notes",
            NSHomeDirectory() + "/Library/Preferences/com.apple.Notes.plist"] where fm.fileExists(atPath: path) {
            c.append(path); notes.append("c: \(path)")
        }
        a = Array(Set(a)).sorted(); b = Array(Set(b)).sorted(); c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2
        var state = CollectedState()
        state.notesMetadataPlane = NotesMetadataPlaneState(
            notesAppPaths: a, notesStorePaths: b, notesContainerPaths: c,
            notesSurfacePresent: surface, notes: notes
        )
        state.collectorNotes[Self.id] = "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
