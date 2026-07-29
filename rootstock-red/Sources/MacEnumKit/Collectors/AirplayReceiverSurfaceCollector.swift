import Foundation
import RootstockCore

/// AirPlay receiver dual-use residual (Wave-16).
/// Safety and behavior: path inventory only; never enables AirPlay Receiver or spoofs AirPlay targets.
public struct AirplayReceiverSurfaceCollector: Collector {
    public static let id = "collect.airplay_receiver_surface"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = ["AirPlay receiver dual-use: path presence only - never enables AirPlay Receiver or spoofs AirPlay targets"]
        var a: [String] = []
        for path in ["/System/Library/PrivateFrameworks/AirPlaySupport.framework",
            "/usr/libexec/airplayd",
            "/System/Library/CoreServices/AirPlayUIAgent.app"] where fm.fileExists(atPath: path) {
            a.append(path); notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in ["/Library/Preferences/com.apple.airplay.plist",
            NSHomeDirectory() + "/Library/Preferences/com.apple.airplay.plist"] where fm.fileExists(atPath: path) {
            b.append(path); notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in ["/System/Library/LaunchDaemons/com.apple.AirPlayXPCHelper.plist",
            "/usr/libexec/AirPlayXPCHelper"] where fm.fileExists(atPath: path) {
            c.append(path); notes.append("c: \(path)")
        }
        a = Array(Set(a)).sorted(); b = Array(Set(b)).sorted(); c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2
        var state = CollectedState()
        state.airplayReceiverSurface = AirplayReceiverSurfaceState(
            airplayDaemonPaths: a, airplayPrefPaths: b, airplayHelperPaths: c,
            airplaySurfacePresent: surface, notes: notes
        )
        state.collectorNotes[Self.id] = "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
