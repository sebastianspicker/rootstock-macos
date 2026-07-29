import Foundation
import RootstockCore

/// App sandbox container residual depth (Wave-15).
/// Safety and behavior: path inventory only; never breaks app sandbox or forges container entitlements.
public struct SandboxContainerDepthCollector: Collector {
    public static let id = "collect.sandbox_container_depth"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = ["Sandbox container depth: path presence only - never breaks app sandbox or forges container entitlements"]
        var a: [String] = []
        for path in [NSHomeDirectory() + "/Library/Containers",
            "/Library/Containers",
            NSHomeDirectory() + "/Library/Group Containers"] where fm.fileExists(atPath: path) {
            a.append(path); notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in ["/System/Library/Sandbox",
            "/usr/share/sandbox",
            "/System/Library/Frameworks/Security.framework"] where fm.fileExists(atPath: path) {
            b.append(path); notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in ["/usr/bin/sandbox-exec",
            "/usr/bin/codesign",
            "/System/Library/PrivateFrameworks/AppSandbox.framework"] where fm.fileExists(atPath: path) {
            c.append(path); notes.append("c: \(path)")
        }
        a = Array(Set(a)).sorted(); b = Array(Set(b)).sorted(); c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2
        var state = CollectedState()
        state.sandboxContainerDepth = SandboxContainerDepthState(
            containerRootPaths: a, sandboxProfilePaths: b, seatbeltSupportPaths: c,
            sandboxSurfacePresent: surface, notes: notes
        )
        state.collectorNotes[Self.id] = "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
