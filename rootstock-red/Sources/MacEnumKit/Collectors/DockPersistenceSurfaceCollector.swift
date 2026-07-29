import Foundation
import RootstockCore

/// Dock persistent apps / recent items dual-use (Wave-12).
///
/// Research basis: public 2025–26 macOS Dock persistence dual-use tradecraft research.
/// Safety and behavior: typed path inventory only; never modifies Dock.plist or plants malicious Dock entries.
public struct DockPersistenceSurfaceCollector: Collector {
    public static let id = "collect.dock_persistence_surface"
    public static let cost: CollectorCost = .low

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = [
            "Dock persistence dual-use: path presence only - never modifies Dock.plist or plants malicious Dock entries",
        ]

        var a: [String] = []
        for path in [NSHomeDirectory() + "/Library/Preferences/com.apple.dock.plist",
            NSHomeDirectory() + "/Library/Preferences/com.apple.dock.extra.plist"] where fm.fileExists(atPath: path) {
            a.append(path)
            notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in [NSHomeDirectory() + "/Library/Application Support/com.apple.sharedfilelist",
            NSHomeDirectory() + "/Library/Application Support/com.apple.sharedfilelist/com.apple.LSSharedFileList.RecentApplications.sfl2",
            NSHomeDirectory() + "/Library/Application Support/com.apple.sharedfilelist/com.apple.LSSharedFileList.RecentDocuments.sfl2"] where fm.fileExists(atPath: path) {
            b.append(path)
            notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in [NSHomeDirectory() + "/Library/Preferences/com.apple.spaces.plist",
            "/System/Library/CoreServices/Dock.app"] where fm.fileExists(atPath: path) {
            c.append(path)
            notes.append("c: \(path)")
        }

        a = Array(Set(a)).sorted()
        b = Array(Set(b)).sorted()
        c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2

        var state = CollectedState()
        state.dockPersistenceSurface = DockPersistenceSurfaceState(
            dockPlistPaths: a,
            recentItemsPaths: b,
            dockDbHints: c,
            dockSurfacePresent: surface,
            notes: notes
        )
        state.collectorNotes[Self.id] =
            "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
