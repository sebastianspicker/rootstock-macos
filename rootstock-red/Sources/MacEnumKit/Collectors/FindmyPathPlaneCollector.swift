import Foundation
import RootstockCore

/// Find My residual path plane (Wave-16).
/// Safety and behavior: path inventory only; never queries Find My device locations or dumps owner tokens.
public struct FindmyPathPlaneCollector: Collector {
    public static let id = "collect.findmy_path_plane"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let inventory = PathPlaneInventorySupport.collect(
            spec: PathPlaneInventorySpec(
                primaryPaths: [
                    "/System/Applications/FindMy.app",
                    "/System/Library/PrivateFrameworks/FindMyDevice.framework",
                    "/usr/libexec/fmfd",
                ],
                secondaryPaths: [
                    NSHomeDirectory() + "/Library/Caches/com.apple.findmy",
                    NSHomeDirectory() + "/Library/Containers/com.apple.findmy",
                ],
                tertiaryPaths: [
                    NSHomeDirectory() + "/Library/Preferences/com.apple.FindMy.plist",
                    "/System/Library/LaunchDaemons/com.apple.fmfd.plist",
                ],
                initialHonestyNote: "Find My path plane: path presence only - never queries Find My device locations or dumps owner tokens"
            )
        )
        var state = CollectedState()
        state.findmyPathPlane = FindmyPathPlaneState(
            findMyAppPaths: inventory.primaryPaths,
            findMyCachePaths: inventory.secondaryPaths,
            fmfdPaths: inventory.tertiaryPaths,
            findmySurfacePresent: inventory.surfacePresent,
            notes: inventory.notes
        )
        state.collectorNotes[Self.id] =
            "a=\(inventory.primaryPaths.count) b=\(inventory.secondaryPaths.count) c=\(inventory.tertiaryPaths.count) surface=\(inventory.surfacePresent)"
        return state
    }
}
