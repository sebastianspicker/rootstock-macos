import Foundation
import RootstockCore

/// PAM authentication module residual surface (Wave-14).
/// Research basis: 2025–26 macOS PAM auth module surface tradecraft.
/// Safety and behavior: path inventory only; never installs PAM modules or modifies /etc/pam.d.
public struct PamAuthModuleCollector: Collector {
    public static let id = "collect.pam_auth_module"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = ["PAM auth module surface: path presence only - never installs PAM modules or modifies /etc/pam.d"]
        var a: [String] = []
        for path in ["/etc/pam.d",
            "/private/etc/pam.d",
            "/etc/pam.d/sudo",
            "/etc/pam.d/authorization"] where fm.fileExists(atPath: path) {
            a.append(path); notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in ["/usr/lib/pam",
            "/usr/local/lib/pam",
            "/Library/Security/SecurityAgentPlugins"] where fm.fileExists(atPath: path) {
            b.append(path); notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in ["/System/Library/PrivateFrameworks/Pam.framework",
            "/usr/libexec/opendirectoryd",
            "/System/Library/LaunchDaemons/com.apple.opendirectoryd.plist"] where fm.fileExists(atPath: path) {
            c.append(path); notes.append("c: \(path)")
        }
        a = Array(Set(a)).sorted(); b = Array(Set(b)).sorted(); c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2
        var state = CollectedState()
        state.pamAuthModule = PamAuthModuleState(
            pamConfigPaths: a, pamModulePaths: b, authdSupportPaths: c,
            pamSurfacePresent: surface, notes: notes
        )
        state.collectorNotes[Self.id] = "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
