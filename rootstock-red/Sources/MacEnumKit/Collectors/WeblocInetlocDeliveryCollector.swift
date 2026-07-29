import Foundation
import RootstockCore

/// Webloc / Internet Location file delivery (Wave-12).
///
/// Research basis: public 2025–26 macOS Webloc/inetloc delivery tradecraft research.
/// Safety and behavior: typed path inventory only; never crafts phishing webloc/inetloc payloads or rewrites Internet Location files.
public struct WeblocInetlocDeliveryCollector: Collector {
    public static let id = "collect.webloc_inetloc_delivery"
    public static let cost: CollectorCost = .low

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = [
            "Webloc/inetloc delivery: path presence only - never crafts phishing webloc/inetloc payloads or rewrites Internet Location files",
        ]

        var a: [String] = []
        for path in [NSHomeDirectory() + "/Downloads",
            NSHomeDirectory() + "/Desktop",
            "/System/Library/CoreServices/Internet Accounts.app"] where fm.fileExists(atPath: path) {
            a.append(path)
            notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in ["/usr/bin/open",
            "/System/Library/Frameworks/CoreServices.framework"] where fm.fileExists(atPath: path) {
            b.append(path)
            notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in [NSHomeDirectory() + "/Downloads",
            NSHomeDirectory() + "/Desktop",
            NSHomeDirectory() + "/Library/Mail Downloads"] where fm.fileExists(atPath: path) {
            c.append(path)
            notes.append("c: \(path)")
        }

        a = Array(Set(a)).sorted()
        b = Array(Set(b)).sorted()
        c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2

        var state = CollectedState()
        state.weblocInetlocDelivery = WeblocInetlocDeliveryState(
            weblocSamplePaths: a,
            inetlocSamplePaths: b,
            dropFolderHints: c,
            deliverySurfacePresent: surface,
            notes: notes
        )
        state.collectorNotes[Self.id] =
            "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
