import Foundation
import RootstockCore

/// FaceTime / camera pipeline dual-use surface (Wave-16).
/// Safety and behavior: path inventory only; never activates camera/mic or dumps FaceTime call history contents.
public struct FacetimeCameraSurfaceCollector: Collector {
    public static let id = "collect.facetime_camera_surface"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let inventory = PathPlaneInventorySupport.collect(
            spec: PathPlaneInventorySpec(
                primaryPaths: [
                    "/System/Applications/FaceTime.app",
                    "/System/Library/PrivateFrameworks/FaceTime.framework",
                    "/System/Library/Frameworks/AVFoundation.framework",
                ],
                secondaryPaths: [
                    "/usr/libexec/avconferenced",
                    "/System/Library/PrivateFrameworks/AVConference.framework",
                ],
                tertiaryPaths: [
                    NSHomeDirectory() + "/Library/Preferences/com.apple.FaceTime.plist",
                    NSHomeDirectory() + "/Library/Application Support/FaceTime",
                ],
                initialHonestyNote: "FaceTime camera dual-use: path presence only - never activates camera/mic or dumps FaceTime call history contents"
            )
        )
        var state = CollectedState()
        state.facetimeCameraSurface = FacetimeCameraSurfaceState(
            facetimeAppPaths: inventory.primaryPaths,
            avConferencePaths: inventory.secondaryPaths,
            facetimePrefPaths: inventory.tertiaryPaths,
            facetimeSurfacePresent: inventory.surfacePresent,
            notes: inventory.notes
        )
        state.collectorNotes[Self.id] =
            "a=\(inventory.primaryPaths.count) b=\(inventory.secondaryPaths.count) c=\(inventory.tertiaryPaths.count) surface=\(inventory.surfacePresent)"
        return state
    }
}
