import Foundation
import RootstockCore

/// Continuity / AirDrop proximity transfer posture (Wave-7).
///
/// Research basis: HackTricks / PEASS AirDrop preference checks.
/// Safety and behavior: typed `ContinuityAirDropState`; never scrapes pasteboard or forces AirDrop sends.
public struct ContinuityAirDropCollector: Collector {
    public static let id = "collect.continuity_airdrop"
    public static let cost: CollectorCost = .low

    private static let airdropPrefPaths: [String] = [
        "/Library/Preferences/com.apple.sharingd.plist",
        NSHomeDirectory() + "/Library/Preferences/com.apple.sharingd.plist",
        NSHomeDirectory() + "/Library/Preferences/com.apple.NetworkBrowser.plist",
        "/Library/Preferences/com.apple.Bluetooth.plist",
        NSHomeDirectory() + "/Library/Preferences/com.apple.Bluetooth.plist",
        NSHomeDirectory() + "/Library/Preferences/ByHost",
    ]

    private static let continuityFrameworkPaths: [String] = [
        "/System/Library/PrivateFrameworks/Sharing.framework",
        "/System/Library/PrivateFrameworks/IDS.framework",
        "/System/Library/PrivateFrameworks/CoreUtils.framework",
        "/System/Library/PrivateFrameworks/Handoff.framework",
        "/usr/libexec/sharingd",
        "/System/Library/LaunchAgents/com.apple.sharingd.plist",
        "/System/Library/LaunchDaemons/com.apple.bluetoothd.plist",
    ]

    private static let nearbyShareHints: [String] = [
        "/usr/libexec/rapportd",
        "/System/Library/LaunchAgents/com.apple.rapportd.plist",
        "/System/Library/PrivateFrameworks/Rapport.framework",
        "/System/Library/CoreServices/ControlCenter.app",
    ]

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = [
            "Continuity/AirDrop surface: pref/framework path presence - no pasteboard scrape, no send",
        ]

        var airdrop: [String] = []
        for path in Self.airdropPrefPaths where fm.fileExists(atPath: path) {
                airdrop.append(path)
                notes.append("airdrop_or_share_pref: \(path)")
        }

        var continuity: [String] = []
        for path in Self.continuityFrameworkPaths where fm.fileExists(atPath: path) {
                continuity.append(path)
                notes.append("continuity_component: \(path)")
        }

        var nearby: [String] = []
        for path in Self.nearbyShareHints where fm.fileExists(atPath: path) {
                nearby.append(path)
                notes.append("nearby_share_hint: \(path)")
        }

        airdrop = Array(Set(airdrop)).sorted()
        continuity = Array(Set(continuity)).sorted()
        nearby = Array(Set(nearby)).sorted()

        let surface = !airdrop.isEmpty || !continuity.isEmpty || !nearby.isEmpty

        var state = CollectedState()
        state.continuityAirDrop = ContinuityAirDropState(
            airdropPrefPaths: airdrop,
            continuityFrameworkPaths: continuity,
            nearbyShareHints: nearby,
            proximitySurfacePresent: surface,
            notes: notes
        )
        state.collectorNotes[Self.id] =
            "airdropPrefs=\(airdrop.count) continuity=\(continuity.count) "
            + "nearby=\(nearby.count) surface=\(surface)"
        return state
    }
}
