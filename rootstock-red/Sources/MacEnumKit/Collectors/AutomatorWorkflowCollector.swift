import Foundation
import RootstockCore

/// Automator workflow delivery residual (Wave-14).
/// Research basis: 2025–26 macOS Automator workflow delivery tradecraft.
/// Safety and behavior: path inventory only; never executes Automator workflows or plants malicious .workflow bundles.
public struct AutomatorWorkflowCollector: Collector {
    public static let id = "collect.automator_workflow"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = ["Automator workflow delivery: path presence only - never executes Automator workflows or plants malicious .workflow bundles"]
        var a: [String] = []
        for path in ["/System/Applications/Automator.app",
            "/Applications/Automator.app",
            NSHomeDirectory() + "/Library/Automator"] where fm.fileExists(atPath: path) {
            a.append(path); notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in [NSHomeDirectory() + "/Library/Services",
            NSHomeDirectory() + "/Library/Workflows",
            NSHomeDirectory() + "/Downloads"] where fm.fileExists(atPath: path) {
            b.append(path); notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in ["/System/Library/Automator",
            "/System/Library/PrivateFrameworks/Automator.framework",
            "/usr/bin/automator"] where fm.fileExists(atPath: path) {
            c.append(path); notes.append("c: \(path)")
        }
        a = Array(Set(a)).sorted(); b = Array(Set(b)).sorted(); c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2
        var state = CollectedState()
        state.automatorWorkflow = AutomatorWorkflowState(
            automatorAppPaths: a, workflowSamplePaths: b, actionLibraryPaths: c,
            workflowSurfacePresent: surface, notes: notes
        )
        state.collectorNotes[Self.id] = "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
