import Foundation
import RootstockCore

/// Wallet / pass residual path plane (Wave-16).
/// Safety and behavior: path inventory only; never dumps pass contents, payment tokens, or card data.
public struct WalletPassPathCollector: Collector {
    public static let id = "collect.wallet_pass_path"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = ["Wallet pass path: path presence only - never dumps pass contents, payment tokens, or card data"]
        var a: [String] = []
        for path in ["/System/Applications/Wallet.app",
            "/System/Library/Frameworks/PassKit.framework",
            "/usr/libexec/passd"] where fm.fileExists(atPath: path) {
            a.append(path); notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in [NSHomeDirectory() + "/Library/Passes",
            NSHomeDirectory() + "/Library/Containers/com.apple.Passbook"] where fm.fileExists(atPath: path) {
            b.append(path); notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in [NSHomeDirectory() + "/Library/Preferences/com.apple.Passbook.plist",
            "/System/Library/PrivateFrameworks/PassKitCore.framework"] where fm.fileExists(atPath: path) {
            c.append(path); notes.append("c: \(path)")
        }
        a = Array(Set(a)).sorted(); b = Array(Set(b)).sorted(); c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2
        var state = CollectedState()
        state.walletPassPath = WalletPassPathState(
            walletAppPaths: a, passesStorePaths: b, passdPaths: c,
            walletSurfacePresent: surface, notes: notes
        )
        state.collectorNotes[Self.id] = "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
