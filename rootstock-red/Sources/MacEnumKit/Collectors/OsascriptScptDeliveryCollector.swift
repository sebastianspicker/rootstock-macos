import Foundation
import RootstockCore

/// Compiled AppleScript / OSA delivery residual (Wave-12).
///
/// Research basis: public 2025–26 macOS OSA/scpt delivery tradecraft research.
/// Safety and behavior: typed path inventory only; never compiles malicious .scpt payloads or executes third-party AppleScripts.
public struct OsascriptScptDeliveryCollector: Collector {
    public static let id = "collect.osascript_scpt_delivery"
    public static let cost: CollectorCost = .low

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = [
            "OSA/scpt delivery: path presence only - never compiles malicious .scpt payloads or executes third-party AppleScripts",
        ]

        var a: [String] = []
        for path in ["/usr/bin/osascript",
            "/usr/bin/osacompile",
            "/usr/bin/osalang"] where fm.fileExists(atPath: path) {
            a.append(path)
            notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in ["/System/Applications/Utilities/Script Editor.app",
            "/Applications/Utilities/Script Editor.app",
            "/System/Library/Frameworks/OSAKit.framework"] where fm.fileExists(atPath: path) {
            b.append(path)
            notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in [NSHomeDirectory() + "/Downloads",
            NSHomeDirectory() + "/Desktop",
            NSHomeDirectory() + "/Library/Scripts"] where fm.fileExists(atPath: path) {
            c.append(path)
            notes.append("c: \(path)")
        }

        a = Array(Set(a)).sorted()
        b = Array(Set(b)).sorted()
        c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2

        var state = CollectedState()
        state.osascriptScptDelivery = OsascriptScptDeliveryState(
            osaToolPaths: a,
            scriptEditorPaths: b,
            scptDropHints: c,
            scptSurfacePresent: surface,
            notes: notes
        )
        state.collectorNotes[Self.id] =
            "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
