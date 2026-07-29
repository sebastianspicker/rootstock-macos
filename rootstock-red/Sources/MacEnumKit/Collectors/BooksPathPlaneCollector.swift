import Foundation
import RootstockCore

/// Books / EPUB path residual plane (Wave-16).
/// Safety and behavior: path inventory only; never extracts EPUB contents or Books annotations as bulk export.
public struct BooksPathPlaneCollector: Collector {
    public static let id = "collect.books_path_plane"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = ["Books path plane: path presence only - never extracts EPUB contents or Books annotations as bulk export"]
        var a: [String] = []
        for path in ["/System/Applications/Books.app",
            "/System/Library/PrivateFrameworks/BookLibraryCore.framework"] where fm.fileExists(atPath: path) {
            a.append(path); notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in [NSHomeDirectory() + "/Library/Containers/com.apple.iBooksX",
            NSHomeDirectory() + "/Library/Mobile Documents/iCloud~com~apple~iBooks"] where fm.fileExists(atPath: path) {
            b.append(path); notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in [NSHomeDirectory() + "/Library/Preferences/com.apple.iBooksX.plist",
            "/System/Library/PrivateFrameworks/BookKit.framework"] where fm.fileExists(atPath: path) {
            c.append(path); notes.append("c: \(path)")
        }
        a = Array(Set(a)).sorted(); b = Array(Set(b)).sorted(); c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2
        var state = CollectedState()
        state.booksPathPlane = BooksPathPlaneState(
            booksAppPaths: a, booksContainerPaths: b, booksPrefPaths: c,
            booksSurfacePresent: surface, notes: notes
        )
        state.collectorNotes[Self.id] = "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
