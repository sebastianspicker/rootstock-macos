import Foundation
import RootstockCore

/// Emond legacy rules residual depth (Wave-15).
/// Safety and behavior: path inventory only; never installs emond rules or enables the legacy event monitor daemon.
public struct EmondLegacyDepthCollector: Collector {
    public static let id = "collect.emond_legacy_depth"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = ["Emond legacy depth: path presence only - never installs emond rules or enables the legacy event monitor daemon"]
        var a: [String] = []
        for path in ["/sbin/emond",
            "/usr/libexec/emond",
            "/System/Library/LaunchDaemons/com.apple.emond.plist"] where fm.fileExists(atPath: path) {
            a.append(path); notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in ["/etc/emond.d/rules",
            "/private/etc/emond.d/rules",
            "/etc/emond.d"] where fm.fileExists(atPath: path) {
            b.append(path); notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in ["/System/Library/PrivateFrameworks/Emond.framework",
            "/usr/libexec/emond-helper"] where fm.fileExists(atPath: path) {
            c.append(path); notes.append("c: \(path)")
        }
        a = Array(Set(a)).sorted(); b = Array(Set(b)).sorted(); c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2
        var state = CollectedState()
        state.emondLegacyDepth = EmondLegacyDepthState(
            emondBinaryPaths: a, emondRulePaths: b, emondSupportPaths: c,
            emondSurfacePresent: surface, notes: notes
        )
        state.collectorNotes[Self.id] = "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
