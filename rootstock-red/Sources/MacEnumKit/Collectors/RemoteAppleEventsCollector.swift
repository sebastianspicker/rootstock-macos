import Foundation
import RootstockCore

/// Remote Apple Events / EPPC / Automation lateral posture (Wave-8).
///
/// Research basis: Remote Apple Events / ARD lateral checklists; EPPC historical surface.
/// Safety and behavior: typed `RemoteAppleEventsState`; never enables RAE or sends AppleEvents.
public struct RemoteAppleEventsCollector: Collector {
    public static let id = "collect.remote_apple_events"
    public static let cost: CollectorCost = .low

    private static let remoteAEPrefPaths: [String] = [
        "/Library/Preferences/com.apple.RemoteManagement.plist",
        "/Library/Preferences/com.apple.RemoteDesktop.plist",
        NSHomeDirectory() + "/Library/Preferences/com.apple.RemoteDesktop.plist",
        "/Library/Preferences/com.apple.AppleFileServer.plist",
        "/private/var/db/dslocal/nodes/Default/config/SharePoints",
        "/System/Library/LaunchDaemons/com.apple.AEServer.plist",
        "/System/Library/LaunchDaemons/com.apple.screensharing.plist",
    ]

    private static let eppcFrameworkPaths: [String] = [
        "/System/Library/Frameworks/ScriptingBridge.framework",
        "/System/Library/Frameworks/Carbon.framework/Frameworks/HIToolbox.framework",
        "/System/Library/PrivateFrameworks/AppleScript.framework",
        "/usr/libexec/AEServer",
        "/System/Library/CoreServices/RemoteManagement",
        "/System/Library/CoreServices/RemoteManagement/ARDAgent.app",
        "/System/Library/CoreServices/SystemUIServer.app",
    ]

    private static let remoteMgmtHints: [String] = [
        "/System/Library/CoreServices/RemoteManagement/screensharingd.bundle",
        "/System/Library/LaunchDaemons/com.apple.screensharing.agent.plist",
        "/usr/libexec/sshd-keygen-wrapper",
        "/etc/ssh/sshd_config",
        "/System/Library/LaunchDaemons/ssh.plist",
    ]

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = [
            "Remote Apple Events surface: pref/framework path presence - never enables RAE or sends AE",
        ]

        var prefs: [String] = []
        for path in Self.remoteAEPrefPaths where fm.fileExists(atPath: path) {
            prefs.append(path)
            notes.append("remote_ae_pref: \(path)")
        }

        var eppc: [String] = []
        for path in Self.eppcFrameworkPaths where fm.fileExists(atPath: path) {
            eppc.append(path)
            notes.append("eppc_or_ae_component: \(path)")
        }

        var remote: [String] = []
        for path in Self.remoteMgmtHints where fm.fileExists(atPath: path) {
            remote.append(path)
            notes.append("remote_mgmt_hint: \(path)")
        }

        prefs = Array(Set(prefs)).sorted()
        eppc = Array(Set(eppc)).sorted()
        remote = Array(Set(remote)).sorted()

        let surface = !prefs.isEmpty || eppc.count >= 2 || !remote.isEmpty

        var state = CollectedState()
        state.remoteAppleEvents = RemoteAppleEventsState(
            remoteAEPrefPaths: prefs,
            eppcFrameworkPaths: eppc,
            remoteMgmtHints: remote,
            remoteAutomationSurfacePresent: surface,
            notes: notes
        )
        state.collectorNotes[Self.id] =
            "prefs=\(prefs.count) eppc=\(eppc.count) remote=\(remote.count) surface=\(surface)"
        return state
    }
}
