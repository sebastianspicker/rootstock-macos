import Foundation
import RootstockCore

/// HomeKit residual path plane (Wave-16).
/// Safety and behavior: path inventory only; never enumerates HomeKit accessory secrets or pairs devices.
public struct HomekitPathPlaneCollector: Collector {
    public static let id = "collect.homekit_path_plane"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let inventory = PathPlaneInventorySupport.collect(
            spec: PathPlaneInventorySpec(
                primaryPaths: [
                    "/System/Applications/Home.app",
                    "/System/Library/Frameworks/HomeKit.framework",
                    "/usr/libexec/homed",
                ],
                secondaryPaths: [
                    NSHomeDirectory() + "/Library/HomeKit",
                    NSHomeDirectory() + "/Library/Group Containers/group.com.apple.home",
                ],
                tertiaryPaths: [
                    NSHomeDirectory() + "/Library/Preferences/com.apple.Home.plist",
                    "/System/Library/LaunchDaemons/com.apple.homed.plist",
                ],
                initialHonestyNote: "HomeKit path plane: path presence only - never enumerates HomeKit accessory secrets or pairs devices"
            )
        )
        var state = CollectedState()
        state.homekitPathPlane = HomekitPathPlaneState(
            homeAppPaths: inventory.primaryPaths,
            homeKitStorePaths: inventory.secondaryPaths,
            homedPaths: inventory.tertiaryPaths,
            homekitSurfacePresent: inventory.surfacePresent,
            notes: inventory.notes
        )
        state.collectorNotes[Self.id] =
            "a=\(inventory.primaryPaths.count) b=\(inventory.secondaryPaths.count) c=\(inventory.tertiaryPaths.count) surface=\(inventory.surfacePresent)"
        return state
    }
}
