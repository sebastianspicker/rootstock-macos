import Foundation
import RootstockCore

/// Device management profile residual depth (Wave-16).
/// Safety and behavior: path inventory only; never installs configuration profiles or enrolls hosts in MDM.
public struct DevicemanagementProfileCollector: Collector {
    public static let id = "collect.devicemanagement_profile"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = ["Device management profile: path presence only - never installs configuration profiles or enrolls hosts in MDM"]
        var a: [String] = []
        for path in ["/usr/bin/profiles",
            "/System/Library/PrivateFrameworks/ConfigurationProfiles.framework",
            "/usr/libexec/mdmclient"] where fm.fileExists(atPath: path) {
            a.append(path); notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in ["/Library/Managed Preferences",
            "/var/db/ConfigurationProfiles",
            "/Library/ConfigurationProfiles"] where fm.fileExists(atPath: path) {
            b.append(path); notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in ["/System/Library/LaunchDaemons/com.apple.mdmclient.daemon.plist",
            "/Library/Preferences/com.apple.mdmclient.plist"] where fm.fileExists(atPath: path) {
            c.append(path); notes.append("c: \(path)")
        }
        a = Array(Set(a)).sorted(); b = Array(Set(b)).sorted(); c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2
        var state = CollectedState()
        state.devicemanagementProfile = DevicemanagementProfileState(
            profilesToolPaths: a, managedPrefPaths: b, mdmClientPaths: c,
            deviceMgmtSurfacePresent: surface, notes: notes
        )
        state.collectorNotes[Self.id] = "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
