import Foundation
import RootstockCore

/// Python runtime dual-use residual surface (Wave-15).
/// Safety and behavior: path inventory only; never executes third-party Python payloads or drops malicious site-packages.
public struct PythonRuntimeDualuseCollector: Collector {
    public static let id = "collect.python_runtime_dualuse"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = ["Python runtime dual-use: path presence only - never executes third-party Python payloads or drops malicious site-packages"]
        var a: [String] = []
        for path in ["/usr/bin/python3",
            "/usr/bin/python",
            "/Library/Developer/CommandLineTools/usr/bin/python3",
            "/opt/homebrew/bin/python3"] where fm.fileExists(atPath: path) {
            a.append(path); notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in ["/Library/Python",
            NSHomeDirectory() + "/Library/Python",
            "/usr/local/lib/python3.9"] where fm.fileExists(atPath: path) {
            b.append(path); notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in ["/System/Library/Frameworks/Python.framework",
            "/Library/Frameworks/Python.framework",
            NSHomeDirectory() + "/.local/lib"] where fm.fileExists(atPath: path) {
            c.append(path); notes.append("c: \(path)")
        }
        a = Array(Set(a)).sorted(); b = Array(Set(b)).sorted(); c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2
        var state = CollectedState()
        state.pythonRuntimeDualuse = PythonRuntimeDualuseState(
            pythonBinaryPaths: a, sitePackagePaths: b, pythonFrameworkPaths: c,
            pythonSurfacePresent: surface, notes: notes
        )
        state.collectorNotes[Self.id] = "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
