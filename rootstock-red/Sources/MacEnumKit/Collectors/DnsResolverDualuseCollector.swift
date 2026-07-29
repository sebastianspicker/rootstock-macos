import Foundation
import RootstockCore

/// DNS resolver / mDNSResponder dual-use surface (Wave-14).
/// Research basis: 2025–26 macOS DNS resolver dual-use tradecraft.
/// Safety and behavior: path inventory only; never rewrites resolver config or poisons DNS caches.
public struct DnsResolverDualuseCollector: Collector {
    public static let id = "collect.dns_resolver_dualuse"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = ["DNS resolver dual-use: path presence only - never rewrites resolver config or poisons DNS caches"]
        var a: [String] = []
        for path in ["/usr/sbin/mDNSResponder",
            "/System/Library/LaunchDaemons/com.apple.mDNSResponder.plist",
            "/usr/sbin/mDNSResponderHelper"] where fm.fileExists(atPath: path) {
            a.append(path); notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in ["/etc/resolv.conf",
            "/etc/resolver",
            "/Library/Preferences/SystemConfiguration/preferences.plist"] where fm.fileExists(atPath: path) {
            b.append(path); notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in ["/usr/bin/dscacheutil",
            "/usr/bin/scutil",
            "/usr/sbin/networksetup"] where fm.fileExists(atPath: path) {
            c.append(path); notes.append("c: \(path)")
        }
        a = Array(Set(a)).sorted(); b = Array(Set(b)).sorted(); c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2
        var state = CollectedState()
        state.dnsResolverDualuse = DnsResolverDualuseState(
            mdnsResponderPaths: a, resolverConfigPaths: b, dnsToolPaths: c,
            dnsSurfacePresent: surface, notes: notes
        )
        state.collectorNotes[Self.id] = "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
