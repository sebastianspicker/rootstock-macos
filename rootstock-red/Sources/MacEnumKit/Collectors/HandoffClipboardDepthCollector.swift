import Foundation
import RootstockCore

/// Handoff / Universal Clipboard residual depth (Wave-16).
/// Safety and behavior: path inventory only; never reads Universal Clipboard contents or forges Handoff activity.
public struct HandoffClipboardDepthCollector: Collector {
    public static let id = "collect.handoff_clipboard_depth"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = ["Handoff clipboard depth: path presence only - never reads Universal Clipboard contents or forges Handoff activity"]
        var a: [String] = []
        for path in ["/System/Library/PrivateFrameworks/UserActivity.framework",
            "/System/Library/PrivateFrameworks/ClipboardUI.framework",
            "/usr/libexec/sharingd"] where fm.fileExists(atPath: path) {
            a.append(path); notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in [NSHomeDirectory() + "/Library/Preferences/com.apple.coreservices.useractivityd.plist",
            NSHomeDirectory() + "/Library/Caches/com.apple.Pasteboard"] where fm.fileExists(atPath: path) {
            b.append(path); notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in ["/System/Library/LaunchAgents/com.apple.sharingd.plist",
            "/System/Library/PrivateFrameworks/Sharing.framework"] where fm.fileExists(atPath: path) {
            c.append(path); notes.append("c: \(path)")
        }
        a = Array(Set(a)).sorted(); b = Array(Set(b)).sorted(); c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2
        var state = CollectedState()
        state.handoffClipboardDepth = HandoffClipboardDepthState(
            handoffFrameworkPaths: a, clipboardPathHits: b, sharingdPaths: c,
            handoffSurfacePresent: surface, notes: notes
        )
        state.collectorNotes[Self.id] = "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
