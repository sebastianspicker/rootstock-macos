import Foundation
import RootstockCore

/// Podcasts library path residual (Wave-16).
/// Safety and behavior: path inventory only; never dumps podcast episode files or account tokens.
public struct PodcastsPathPlaneCollector: Collector {
    public static let id = "collect.podcasts_path_plane"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let inventory = PathPlaneInventorySupport.collect(
            spec: PathPlaneInventorySpec(
                primaryPaths: [
                    "/System/Applications/Podcasts.app",
                    "/System/Library/PrivateFrameworks/PodcastsFoundation.framework",
                ],
                secondaryPaths: [
                    NSHomeDirectory() + "/Library/Group Containers/243LU875E5.groups.com.apple.podcasts",
                    NSHomeDirectory() + "/Library/Containers/com.apple.podcasts",
                ],
                tertiaryPaths: [
                    NSHomeDirectory() + "/Library/Preferences/com.apple.podcasts.plist",
                    "/System/Library/PrivateFrameworks/PodcastsKit.framework",
                ],
                initialHonestyNote: "Podcasts path plane: path presence only - never dumps podcast episode files or account tokens"
            )
        )
        var state = CollectedState()
        state.podcastsPathPlane = PodcastsPathPlaneState(
            podcastsAppPaths: inventory.primaryPaths,
            podcastsStorePaths: inventory.secondaryPaths,
            podcastsPrefPaths: inventory.tertiaryPaths,
            podcastsSurfacePresent: inventory.surfacePresent,
            notes: inventory.notes
        )
        state.collectorNotes[Self.id] =
            "a=\(inventory.primaryPaths.count) b=\(inventory.secondaryPaths.count) c=\(inventory.tertiaryPaths.count) surface=\(inventory.surfacePresent)"
        return state
    }
}
