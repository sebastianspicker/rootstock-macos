import Foundation
import RootstockCore

/// AirPlay receiver dual-use residual (Wave-16).
/// Safety and behavior: path inventory only; never enables AirPlay Receiver or spoofs AirPlay targets.
public struct AirplayReceiverSurfaceCollector: Collector {
    public static let id = "collect.airplay_receiver_surface"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let inventory = PathPlaneInventorySupport.collect(
            spec: PathPlaneInventorySpec(
                primaryPaths: [
                    "/System/Library/PrivateFrameworks/AirPlaySupport.framework",
                    "/usr/libexec/airplayd",
                    "/System/Library/CoreServices/AirPlayUIAgent.app",
                ],
                secondaryPaths: [
                    "/Library/Preferences/com.apple.airplay.plist",
                    NSHomeDirectory() + "/Library/Preferences/com.apple.airplay.plist",
                ],
                tertiaryPaths: [
                    "/System/Library/LaunchDaemons/com.apple.AirPlayXPCHelper.plist",
                    "/usr/libexec/AirPlayXPCHelper",
                ],
                initialHonestyNote: "AirPlay receiver dual-use: path presence only - never enables AirPlay Receiver or spoofs AirPlay targets"
            )
        )
        var state = CollectedState()
        state.airplayReceiverSurface = AirplayReceiverSurfaceState(
            airplayDaemonPaths: inventory.primaryPaths,
            airplayPrefPaths: inventory.secondaryPaths,
            airplayHelperPaths: inventory.tertiaryPaths,
            airplaySurfacePresent: inventory.surfacePresent,
            notes: inventory.notes
        )
        state.collectorNotes[Self.id] =
            "a=\(inventory.primaryPaths.count) b=\(inventory.secondaryPaths.count) c=\(inventory.tertiaryPaths.count) surface=\(inventory.surfacePresent)"
        return state
    }
}
