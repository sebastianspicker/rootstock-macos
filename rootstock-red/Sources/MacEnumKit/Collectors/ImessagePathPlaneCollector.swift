import Foundation
import RootstockCore

/// iMessage / Messages path collection plane (Wave-16).
/// Safety and behavior: path inventory only; never reads Messages database contents or exports chat transcripts.
public struct ImessagePathPlaneCollector: Collector {
    public static let id = "collect.imessage_path_plane"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = ["iMessage path plane: path presence only - never reads Messages database contents or exports chat transcripts"]
        var a: [String] = []
        for path in ["/System/Applications/Messages.app",
            "/Applications/Messages.app",
            "/System/Library/PrivateFrameworks/IMCore.framework"] where fm.fileExists(atPath: path) {
            a.append(path); notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in [NSHomeDirectory() + "/Library/Messages",
            NSHomeDirectory() + "/Library/Messages/chat.db",
            NSHomeDirectory() + "/Library/Containers/com.apple.iChat"] where fm.fileExists(atPath: path) {
            b.append(path); notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in [NSHomeDirectory() + "/Library/Preferences/com.apple.iChat.plist",
            "/System/Library/PrivateFrameworks/IMFoundation.framework"] where fm.fileExists(atPath: path) {
            c.append(path); notes.append("c: \(path)")
        }
        a = Array(Set(a)).sorted(); b = Array(Set(b)).sorted(); c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2
        var state = CollectedState()
        state.imessagePathPlane = ImessagePathPlaneState(
            messagesAppPaths: a, messagesDbPaths: b, messagesPrefPaths: c,
            imessageSurfacePresent: surface, notes: notes
        )
        state.collectorNotes[Self.id] = "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
