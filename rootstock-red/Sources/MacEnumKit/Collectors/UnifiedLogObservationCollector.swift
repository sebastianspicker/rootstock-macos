import Foundation
import RootstockCore

/// Unified log / logarchive observation depth (Wave-12).
///
/// Research basis: public 2025–26 macOS Unified log observation tradecraft research.
/// Safety and behavior: typed path inventory only; never dumps private unified-log message bodies or force-collects other users' logarchives.
public struct UnifiedLogObservationCollector: Collector {
    public static let id = "collect.unified_log_observation"
    public static let cost: CollectorCost = .low

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = [
            "Unified log observation: path presence only - never dumps private unified-log message bodies or force-collects other users' logarchives",
        ]

        var a: [String] = []
        for path in ["/usr/bin/log",
            "/System/Library/PrivateFrameworks/LoggingSupport.framework",
            "/usr/libexec/logd"] where fm.fileExists(atPath: path) {
            a.append(path)
            notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in [NSHomeDirectory() + "/Library/Logs",
            "/var/db/diagnostics",
            "/var/db/uuidtext",
            NSHomeDirectory() + "/Downloads"] where fm.fileExists(atPath: path) {
            b.append(path)
            notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in ["/Library/Preferences/Logging",
            "/System/Library/Preferences/Logging",
            NSHomeDirectory() + "/Library/Preferences/com.apple.diagnosticd.plist"] where fm.fileExists(atPath: path) {
            c.append(path)
            notes.append("c: \(path)")
        }

        a = Array(Set(a)).sorted()
        b = Array(Set(b)).sorted()
        c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2

        var state = CollectedState()
        state.unifiedLogObservation = UnifiedLogObservationState(
            logToolPaths: a,
            logarchiveHints: b,
            privacyPrefPaths: c,
            observationSurfacePresent: surface,
            notes: notes
        )
        state.collectorNotes[Self.id] =
            "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
