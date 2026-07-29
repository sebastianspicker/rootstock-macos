import Foundation
import RootstockCore

/// Bluetooth / Continuity proximity residual depth (Wave-14).
/// Research basis: 2025–26 macOS Bluetooth Continuity depth tradecraft.
/// Safety and behavior: path inventory only; never enables Bluetooth pairing or spoofs Continuity identities.
public struct BluetoothContinuityDepthCollector: Collector {
    public static let id = "collect.bluetooth_continuity_depth"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = ["Bluetooth Continuity depth: path presence only - never enables Bluetooth pairing or spoofs Continuity identities"]
        var a: [String] = []
        for path in ["/usr/sbin/bluetoothd",
            "/System/Library/LaunchDaemons/com.apple.bluetoothd.plist",
            "/usr/sbin/BlueTool"] where fm.fileExists(atPath: path) {
            a.append(path); notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in ["/System/Library/PrivateFrameworks/Sharing.framework",
            "/System/Library/PrivateFrameworks/Continuity.framework",
            "/System/Library/CoreServices/Bluetooth File Exchange.app"] where fm.fileExists(atPath: path) {
            b.append(path); notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in [NSHomeDirectory() + "/Library/Preferences/com.apple.Bluetooth.plist",
            "/Library/Preferences/com.apple.Bluetooth.plist",
            NSHomeDirectory() + "/Library/Preferences/ByHost"] where fm.fileExists(atPath: path) {
            c.append(path); notes.append("c: \(path)")
        }
        a = Array(Set(a)).sorted(); b = Array(Set(b)).sorted(); c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2
        var state = CollectedState()
        state.bluetoothContinuityDepth = BluetoothContinuityDepthState(
            bluetoothDaemonPaths: a, continuitySupportPaths: b, btPreferencePaths: c,
            btContinuitySurfacePresent: surface, notes: notes
        )
        state.collectorNotes[Self.id] = "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
