import Foundation
import RootstockCore

/// XPC Mach service residual depth (Wave-15).
/// Safety and behavior: path inventory only; never registers XPC services or injects into Mach ports.
public struct XpcMachServiceDepthCollector: Collector {
    public static let id = "collect.xpc_mach_service_depth"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = ["XPC Mach service depth: path presence only - never registers XPC services or injects into Mach ports"]
        var a: [String] = []
        for path in ["/usr/libexec/xpcproxy",
            "/System/Library/Frameworks/XPC.framework",
            "/usr/lib/system/libxpc.dylib"] where fm.fileExists(atPath: path) {
            a.append(path); notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in ["/Library/LaunchDaemons",
            "/System/Library/LaunchDaemons",
            NSHomeDirectory() + "/Library/LaunchAgents"] where fm.fileExists(atPath: path) {
            b.append(path); notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in ["/usr/bin/launchctl",
            "/usr/sbin/systemextensionsctl",
            "/Library/PrivilegedHelperTools"] where fm.fileExists(atPath: path) {
            c.append(path); notes.append("c: \(path)")
        }
        a = Array(Set(a)).sorted(); b = Array(Set(b)).sorted(); c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2
        var state = CollectedState()
        state.xpcMachServiceDepth = XpcMachServiceDepthState(
            xpcBootstrapPaths: a, machServicePlistPaths: b, xpcToolPaths: c,
            xpcMachSurfacePresent: surface, notes: notes
        )
        state.collectorNotes[Self.id] = "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
