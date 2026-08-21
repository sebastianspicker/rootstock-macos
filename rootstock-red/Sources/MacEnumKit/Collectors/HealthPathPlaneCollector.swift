import Foundation
import RootstockCore

/// Health app residual path plane (Wave-16).
/// Safety and behavior: path inventory only; never exports HealthKit samples or medical records.
public struct HealthPathPlaneCollector: Collector {
    public static let id = "collect.health_path_plane"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let inventory = PathPlaneInventorySupport.collect(
            spec: PathPlaneInventorySpec(
                primaryPaths: [
                    "/System/Applications/Health.app",
                    "/System/Library/Frameworks/HealthKit.framework",
                    "/usr/libexec/healthd",
                ],
                secondaryPaths: [
                    NSHomeDirectory() + "/Library/Health",
                    NSHomeDirectory() + "/Library/Containers/com.apple.Health",
                ],
                tertiaryPaths: [
                    NSHomeDirectory() + "/Library/Preferences/com.apple.Health.plist",
                    "/System/Library/PrivateFrameworks/HealthDaemon.framework",
                ],
                initialHonestyNote: "Health path plane: path presence only - never exports HealthKit samples or medical records"
            )
        )
        var state = CollectedState()
        state.healthPathPlane = HealthPathPlaneState(
            healthAppPaths: inventory.primaryPaths,
            healthStorePaths: inventory.secondaryPaths,
            healthdPaths: inventory.tertiaryPaths,
            healthSurfacePresent: inventory.surfacePresent,
            notes: inventory.notes
        )
        state.collectorNotes[Self.id] =
            "a=\(inventory.primaryPaths.count) b=\(inventory.secondaryPaths.count) c=\(inventory.tertiaryPaths.count) surface=\(inventory.surfacePresent)"
        return state
    }
}
