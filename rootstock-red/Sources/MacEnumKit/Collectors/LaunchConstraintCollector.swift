import Foundation
import RootstockCore

/// Launch-constraint / library-validation injectability truth (path + codesign note heuristics).
///
/// Research basis: InjectCheck-style HR/LV flags; Apple launch-constraint documentation themes.
/// Safety and behavior: explicit constrained vs unconstrained-risk path sets; never claims process
/// injection success; feeds `LaunchConstraintInjectTruthVector`.
public struct LaunchConstraintCollector: Collector {
    public static let id = "collect.launch_constraints"
    public static let cost: CollectorCost = .medium

    /// Lightweight sample set: common high-value app locations (metadata only).
    private static let sampleRoots: [String] = [
        "/Applications",
        "/usr/local/bin",
        "/opt/homebrew/bin",
    ]

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        var accumulator = CollectionAccumulator()
        for app in Self.sampleApps() {
            Self.process(app: app, accumulator: &accumulator)
        }
        for root in Self.sampleRoots {
            accumulator.notes.append("sample_root_exists=\(FileManager.default.fileExists(atPath: root)): \(root)")
        }
        return Self.state(from: accumulator)
    }

    private struct CollectionAccumulator {
        var notes = ["Launch-constraint honesty: path/codesign heuristics only - no runtime inject"]
        var constrained: [String] = []
        var unconstrainedRisk: [String] = []
        var injectSampleCount = 0
    }

    private static func sampleApps() -> [URL] {
        let root = URL(fileURLWithPath: "/Applications", isDirectory: true)
        let contents = (try? FileManager.default.contentsOfDirectory(
            at: root,
            includingPropertiesForKeys: [.isDirectoryKey],
            options: [.skipsHiddenFiles]
        )) ?? []
        return contents.filter { $0.pathExtension == "app" }.prefix(12).map { $0 }
    }

    private static func process(app: URL, accumulator: inout CollectionAccumulator) {
        let fm = FileManager.default
        let info = app.appendingPathComponent("Contents/Info.plist")
        guard fm.fileExists(atPath: info.path) else { return }
        let constraints = [app.appendingPathComponent("Contents/Library/LaunchConstraints"), app.appendingPathComponent("Contents/Resources/launchd-constraint.plist"), app.appendingPathComponent("Contents/CodeResources")]
        let artifacts = constraints.filter { fm.fileExists(atPath: $0.path) }
        accumulator.constrained.append(contentsOf: artifacts.map(\.path))
        accumulator.notes.append(contentsOf: artifacts.map { "constraint-ish artifact: \($0.path)" })
        let macOS = app.appendingPathComponent("Contents/MacOS", isDirectory: true)
        guard let first = try? fm.contentsOfDirectory(atPath: macOS.path).first else { return }
        let path = macOS.appendingPathComponent(first).path
        let hit = AppSampleSupport.injectabilityHit(from: AppSampleSupport.inspectCodesign(path: path))
        let flags = hit.riskFlags
        if !flags.isEmpty {
            accumulator.injectSampleCount += 1
            if artifacts.isEmpty {
                accumulator.unconstrainedRisk.append(path)
                accumulator.notes.append("risk without constraint artifact: \(path) flags=\(flags.joined(separator: ","))")
            }
        } else if !artifacts.isEmpty {
            accumulator.notes.append("constrained sample with no entitlement risk flags: \(path)")
        }
    }

    private static func state(from accumulator: CollectionAccumulator) -> CollectedState {
        var state = CollectedState()
        state.launchConstraints = LaunchConstraintState(constrainedPaths: Array(Set(accumulator.constrained)).sorted(), unconstrainedRiskPaths: Array(Set(accumulator.unconstrainedRisk)).sorted(), notes: accumulator.notes)
        state.collectorNotes[Self.id] = "constrained=\(accumulator.constrained.count) unconstrainedRisk=\(accumulator.unconstrainedRisk.count) " + "injectSamples=\(accumulator.injectSampleCount)"
        return state
    }
}
