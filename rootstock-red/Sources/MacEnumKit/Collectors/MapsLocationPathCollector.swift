import Foundation
import RootstockCore

/// Maps / location services residual plane (Wave-16).
/// Safety and behavior: path inventory only; never dumps location history or spoofs CoreLocation positions.
public struct MapsLocationPathCollector: Collector {
    public static let id = "collect.maps_location_path"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let inventory = PathPlaneInventorySupport.collect(
            spec: PathPlaneInventorySpec(
                primaryPaths: [
                    "/System/Applications/Maps.app",
                    "/System/Library/Frameworks/CoreLocation.framework",
                    "/usr/libexec/locationd",
                ],
                secondaryPaths: [
                    NSHomeDirectory() + "/Library/Caches/com.apple.Maps",
                    NSHomeDirectory() + "/Library/Containers/com.apple.Maps",
                ],
                tertiaryPaths: [
                    NSHomeDirectory() + "/Library/Preferences/com.apple.Maps.plist",
                    "/System/Library/LaunchDaemons/com.apple.locationd.plist",
                ],
                initialHonestyNote: "Maps location residual: path presence only - never dumps location history or spoofs CoreLocation positions"
            )
        )
        var state = CollectedState()
        state.mapsLocationPath = MapsLocationPathState(
            mapsAppPaths: inventory.primaryPaths,
            mapsCachePaths: inventory.secondaryPaths,
            locationdPaths: inventory.tertiaryPaths,
            mapsLocationSurfacePresent: inventory.surfacePresent,
            notes: inventory.notes
        )
        state.collectorNotes[Self.id] =
            "a=\(inventory.primaryPaths.count) b=\(inventory.secondaryPaths.count) c=\(inventory.tertiaryPaths.count) surface=\(inventory.surfacePresent)"
        return state
    }
}
