import Foundation
import RootstockCore

/// TV.app residual path plane (Wave-16).
/// Safety and behavior: path inventory only; never dumps TV.app media caches or account material.
public struct TvAppPathPlaneCollector: Collector {
    public static let id = "collect.tv_app_path_plane"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let inventory = PathPlaneInventorySupport.collect(
            spec: PathPlaneInventorySpec(
                primaryPaths: [
                    "/System/Applications/TV.app",
                    "/System/Library/PrivateFrameworks/TVPlayback.framework",
                ],
                secondaryPaths: [
                    NSHomeDirectory() + "/Library/Containers/com.apple.TV",
                    NSHomeDirectory() + "/Library/Group Containers/group.com.apple.tv",
                ],
                tertiaryPaths: [
                    NSHomeDirectory() + "/Library/Preferences/com.apple.TV.plist",
                    "/System/Library/PrivateFrameworks/VideosUI.framework",
                ],
                initialHonestyNote: "TV.app path plane: path presence only - never dumps TV.app media caches or account material"
            )
        )
        var state = CollectedState()
        state.tvAppPathPlane = TvAppPathPlaneState(
            tvAppPaths: inventory.primaryPaths,
            tvContainerPaths: inventory.secondaryPaths,
            tvPrefPaths: inventory.tertiaryPaths,
            tvSurfacePresent: inventory.surfacePresent,
            notes: inventory.notes
        )
        state.collectorNotes[Self.id] =
            "a=\(inventory.primaryPaths.count) b=\(inventory.secondaryPaths.count) c=\(inventory.tertiaryPaths.count) surface=\(inventory.surfacePresent)"
        return state
    }
}
