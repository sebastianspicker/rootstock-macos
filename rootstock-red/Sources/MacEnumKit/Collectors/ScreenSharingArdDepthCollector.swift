import Foundation
import RootstockCore

/// Screen Sharing / ARD residual depth (Wave-15).
/// Safety and behavior: path inventory only; never enables Screen Sharing or ARD, never connects to remote desktops.
public struct ScreenSharingArdDepthCollector: Collector {
    public static let id = "collect.screen_sharing_ard_depth"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = ["Screen Sharing ARD depth: path presence only - never enables Screen Sharing or ARD, never connects to remote desktops"]
        var a: [String] = []
        for path in ["/System/Library/CoreServices/RemoteManagement/AppleVNCServer.bundle",
            "/System/Library/CoreServices/RemoteManagement/screensharingd.bundle",
            "/System/Applications/Utilities/Screen Sharing.app"] where fm.fileExists(atPath: path) {
            a.append(path); notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in ["/System/Library/CoreServices/RemoteManagement/ARDAgent.app",
            "/Library/Application Support/Apple/Remote Desktop",
            "/System/Library/LaunchDaemons/com.apple.screensharing.plist"] where fm.fileExists(atPath: path) {
            b.append(path); notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in ["/Library/Preferences/com.apple.RemoteManagement.plist",
            "/Library/Preferences/com.apple.screensharing.plist",
            NSHomeDirectory() + "/Library/Preferences/com.apple.screensharing.plist"] where fm.fileExists(atPath: path) {
            c.append(path); notes.append("c: \(path)")
        }
        a = Array(Set(a)).sorted(); b = Array(Set(b)).sorted(); c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2
        var state = CollectedState()
        state.screenSharingArdDepth = ScreenSharingArdDepthState(
            screenSharingAppPaths: a, ardAgentPaths: b, remoteMgmtPrefPaths: c,
            ardSurfacePresent: surface, notes: notes
        )
        state.collectorNotes[Self.id] = "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
