import Foundation
import RootstockCore

/// Spotlight importer residual depth (Wave-16).
/// Safety and behavior: path inventory only; never installs malicious Spotlight importers or dumps mdworker index contents.
public struct SpotlightImporterDepthCollector: Collector {
    public static let id = "collect.spotlight_importer_depth"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = ["Spotlight importer depth: path presence only - never installs malicious Spotlight importers or dumps mdworker index contents"]
        var a: [String] = []
        for path in ["/System/Library/Frameworks/CoreServices.framework/Frameworks/Metadata.framework",
            "/usr/bin/mdimport",
            "/usr/bin/mdfind"] where fm.fileExists(atPath: path) {
            a.append(path); notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in ["/Library/Spotlight",
            NSHomeDirectory() + "/Library/Spotlight",
            "/System/Library/Spotlight"] where fm.fileExists(atPath: path) {
            b.append(path); notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in ["/System/Library/LaunchDaemons/com.apple.metadata.mds.plist",
            "/System/Library/Frameworks/CoreSpotlight.framework"] where fm.fileExists(atPath: path) {
            c.append(path); notes.append("c: \(path)")
        }
        a = Array(Set(a)).sorted(); b = Array(Set(b)).sorted(); c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2
        var state = CollectedState()
        state.spotlightImporterDepth = SpotlightImporterDepthState(
            metadataToolPaths: a, spotlightImporterPaths: b, mdsLaunchPaths: c,
            spotlightImporterSurfacePresent: surface, notes: notes
        )
        state.collectorNotes[Self.id] = "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
