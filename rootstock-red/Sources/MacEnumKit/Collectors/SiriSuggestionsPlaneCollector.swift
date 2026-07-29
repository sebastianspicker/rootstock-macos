import Foundation
import RootstockCore

/// Siri / Suggestions data-access residual (Wave-16).
/// Safety and behavior: path inventory only; never dumps Siri transcripts or Suggestions databases contents.
public struct SiriSuggestionsPlaneCollector: Collector {
    public static let id = "collect.siri_suggestions_plane"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = ["Siri Suggestions residual: path presence only - never dumps Siri transcripts or Suggestions databases contents"]
        var a: [String] = []
        for path in ["/System/Library/PrivateFrameworks/AssistantServices.framework",
            "/System/Library/PrivateFrameworks/SiriUI.framework",
            "/System/Library/CoreServices/Siri.app"] where fm.fileExists(atPath: path) {
            a.append(path); notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in [NSHomeDirectory() + "/Library/Assistant",
            NSHomeDirectory() + "/Library/Suggestions",
            NSHomeDirectory() + "/Library/DuetExpertCenter"] where fm.fileExists(atPath: path) {
            b.append(path); notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in [NSHomeDirectory() + "/Library/Preferences/com.apple.assistant.plist",
            "/System/Library/LaunchAgents/com.apple.assistantd.plist"] where fm.fileExists(atPath: path) {
            c.append(path); notes.append("c: \(path)")
        }
        a = Array(Set(a)).sorted(); b = Array(Set(b)).sorted(); c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2
        var state = CollectedState()
        state.siriSuggestionsPlane = SiriSuggestionsPlaneState(
            siriFrameworkPaths: a, suggestionsStorePaths: b, siriPrefPaths: c,
            siriSurfacePresent: surface, notes: notes
        )
        state.collectorNotes[Self.id] = "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
