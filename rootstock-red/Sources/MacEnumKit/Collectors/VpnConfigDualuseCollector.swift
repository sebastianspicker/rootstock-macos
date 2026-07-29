import Foundation
import RootstockCore

/// VPN configuration dual-use residual surface (Wave-15).
/// Safety and behavior: path inventory only; never installs VPN profiles or rewrites network extension VPN configs.
public struct VpnConfigDualuseCollector: Collector {
    public static let id = "collect.vpn_config_dualuse"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = ["VPN config dual-use: path presence only - never installs VPN profiles or rewrites network extension VPN configs"]
        var a: [String] = []
        for path in ["/System/Library/Frameworks/NetworkExtension.framework",
            "/System/Library/PrivateFrameworks/NetworkExtension.framework",
            "/usr/libexec/neagent"] where fm.fileExists(atPath: path) {
            a.append(path); notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in ["/Library/Preferences/com.apple.networkextension.plist",
            NSHomeDirectory() + "/Library/Preferences/com.apple.networkextension.plist",
            "/Library/Preferences/SystemConfiguration"] where fm.fileExists(atPath: path) {
            b.append(path); notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in ["/usr/sbin/networksetup",
            "/usr/sbin/scutil",
            "/usr/bin/profiles"] where fm.fileExists(atPath: path) {
            c.append(path); notes.append("c: \(path)")
        }
        a = Array(Set(a)).sorted(); b = Array(Set(b)).sorted(); c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2
        var state = CollectedState()
        state.vpnConfigDualuse = VpnConfigDualuseState(
            vpnFrameworkPaths: a, vpnPrefPaths: b, vpnToolPaths: c,
            vpnSurfacePresent: surface, notes: notes
        )
        state.collectorNotes[Self.id] = "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
