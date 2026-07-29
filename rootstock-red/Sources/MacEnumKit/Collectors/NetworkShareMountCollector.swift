import Foundation
import RootstockCore

/// Network share / SMB mount dual-use lateral (Wave-12).
///
/// Research basis: public 2025–26 macOS Network share mount tradecraft research.
/// Safety and behavior: typed path inventory only; never mounts attacker shares or writes credentials to NetAuth.
public struct NetworkShareMountCollector: Collector {
    public static let id = "collect.network_share_mount"
    public static let cost: CollectorCost = .low

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = [
            "Network share mount: path presence only - never mounts attacker shares or writes credentials to NetAuth",
        ]

        var a: [String] = []
        for path in ["/usr/bin/smbutil",
            "/System/Library/CoreServices/NetAuthAgent.app",
            "/System/Library/PrivateFrameworks/NetAuth.framework",
            "/sbin/mount_smbfs"] where fm.fileExists(atPath: path) {
            a.append(path)
            notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in [NSHomeDirectory() + "/Library/Preferences/nsmb.conf",
            "/etc/nsmb.conf",
            NSHomeDirectory() + "/Library/Preferences/com.apple.NetworkAuthorization.plist"] where fm.fileExists(atPath: path) {
            b.append(path)
            notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in ["/Volumes",
            NSHomeDirectory() + "/Library/Application Support/AddressBook"] where fm.fileExists(atPath: path) {
            c.append(path)
            notes.append("c: \(path)")
        }

        a = Array(Set(a)).sorted()
        b = Array(Set(b)).sorted()
        c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2

        var state = CollectedState()
        state.networkShareMount = NetworkShareMountState(
            smbClientPaths: a,
            netAuthPaths: b,
            mountPointHints: c,
            shareSurfacePresent: surface,
            notes: notes
        )
        state.collectorNotes[Self.id] =
            "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
