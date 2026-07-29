import Foundation
import RootstockCore

/// Keychain ACL path residual surface (Wave-15).
/// Safety and behavior: path inventory only; never dumps keychain items, passwords, or private keys.
public struct KeychainAclPathCollector: Collector {
    public static let id = "collect.keychain_acl_path"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = ["Keychain ACL path plane: path presence only - never dumps keychain items, passwords, or private keys"]
        var a: [String] = []
        for path in [NSHomeDirectory() + "/Library/Keychains",
            NSHomeDirectory() + "/Library/Keychains/login.keychain-db",
            "/Library/Keychains"] where fm.fileExists(atPath: path) {
            a.append(path); notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in ["/usr/bin/security",
            "/System/Library/Frameworks/Security.framework",
            "/usr/libexec/keychain-agent"] where fm.fileExists(atPath: path) {
            b.append(path); notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in ["/System/Library/PrivateFrameworks/KeychainAccess.framework",
            NSHomeDirectory() + "/Library/Preferences/com.apple.security.plist"] where fm.fileExists(atPath: path) {
            c.append(path); notes.append("c: \(path)")
        }
        a = Array(Set(a)).sorted(); b = Array(Set(b)).sorted(); c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2
        var state = CollectedState()
        state.keychainAclPath = KeychainAclPathState(
            keychainDbPaths: a, securityToolPaths: b, keychainSupportPaths: c,
            keychainAclSurfacePresent: surface, notes: notes
        )
        state.collectorNotes[Self.id] = "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
