import Foundation
import RootstockCore

/// QuickLook thumbnail cache residual depth (Wave-14).
/// Research basis: 2025–26 macOS QuickLook cache depth tradecraft.
/// Safety and behavior: path inventory only; never dumps QuickLook thumbnail bitmap contents as secret material.
public struct QuicklookCacheDepthCollector: Collector {
    public static let id = "collect.quicklook_cache_depth"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = ["QuickLook cache depth: path presence only - never dumps QuickLook thumbnail bitmap contents as secret material"]
        var a: [String] = []
        for path in ["/System/Library/Frameworks/QuickLook.framework",
            "/System/Library/PrivateFrameworks/QuickLookThumbnailing.framework",
            "/usr/bin/qlmanage"] where fm.fileExists(atPath: path) {
            a.append(path); notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in [NSHomeDirectory() + "/Library/Caches/com.apple.QuickLook.thumbnailcache",
            NSHomeDirectory() + "/Library/QuickLook",
            "/private/var/folders"] where fm.fileExists(atPath: path) {
            b.append(path); notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in ["/System/Library/QuickLook",
            NSHomeDirectory() + "/Library/Preferences/com.apple.QuickLookDaemon.plist"] where fm.fileExists(atPath: path) {
            c.append(path); notes.append("c: \(path)")
        }
        a = Array(Set(a)).sorted(); b = Array(Set(b)).sorted(); c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2
        var state = CollectedState()
        state.quicklookCacheDepth = QuicklookCacheDepthState(
            quicklookDaemonPaths: a, thumbnailCachePaths: b, qlmanagePaths: c,
            quicklookSurfacePresent: surface, notes: notes
        )
        state.collectorNotes[Self.id] = "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
