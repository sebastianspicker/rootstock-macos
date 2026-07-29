import Foundation
import RootstockCore

/// Finder Sync extension dual-use surface (Wave-16).
/// Safety and behavior: path inventory only; never installs Finder Sync extensions or rewrites Finder preferences for abuse.
public struct FinderSyncExtensionCollector: Collector {
    public static let id = "collect.finder_sync_extension"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = ["Finder Sync dual-use: path presence only - never installs Finder Sync extensions or rewrites Finder preferences for abuse"]
        var a: [String] = []
        for path in ["/System/Library/Frameworks/FinderSync.framework",
            "/System/Library/CoreServices/Finder.app"] where fm.fileExists(atPath: path) {
            a.append(path); notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in [NSHomeDirectory() + "/Library/Application Scripts",
            "/Library/Application Support"] where fm.fileExists(atPath: path) {
            b.append(path); notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in [NSHomeDirectory() + "/Library/Preferences/com.apple.finder.plist",
            "/System/Library/PrivateFrameworks/FileProvider.framework"] where fm.fileExists(atPath: path) {
            c.append(path); notes.append("c: \(path)")
        }
        a = Array(Set(a)).sorted(); b = Array(Set(b)).sorted(); c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2
        var state = CollectedState()
        state.finderSyncExtension = FinderSyncExtensionState(
            finderSyncFrameworkPaths: a, appScriptPaths: b, finderPrefPaths: c,
            finderSyncSurfacePresent: surface, notes: notes
        )
        state.collectorNotes[Self.id] = "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
