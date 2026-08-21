import Foundation
import RootstockCore

/// Reminders cloud path residual plane (Wave-16).
/// Safety and behavior: path inventory only; never reads reminder titles/bodies or exports Reminders databases.
public struct RemindersCloudPathCollector: Collector {
    public static let id = "collect.reminders_cloud_path"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let inventory = PathPlaneInventorySupport.collect(
            spec: PathPlaneInventorySpec(
                primaryPaths: [
                    "/System/Applications/Reminders.app",
                    "/System/Library/PrivateFrameworks/ReminderKit.framework",
                ],
                secondaryPaths: [
                    NSHomeDirectory() + "/Library/Reminders",
                    NSHomeDirectory() + "/Library/Group Containers/group.com.apple.reminders",
                ],
                tertiaryPaths: [
                    NSHomeDirectory() + "/Library/Preferences/com.apple.reminders.plist",
                    "/System/Library/PrivateFrameworks/RemindersUICore.framework",
                ],
                initialHonestyNote: "Reminders cloud path: path presence only - never reads reminder titles/bodies or exports Reminders databases"
            )
        )
        var state = CollectedState()
        state.remindersCloudPath = RemindersCloudPathState(
            remindersAppPaths: inventory.primaryPaths,
            remindersStorePaths: inventory.secondaryPaths,
            remindersPrefPaths: inventory.tertiaryPaths,
            remindersCloudSurfacePresent: inventory.surfacePresent,
            notes: inventory.notes
        )
        state.collectorNotes[Self.id] =
            "a=\(inventory.primaryPaths.count) b=\(inventory.secondaryPaths.count) c=\(inventory.tertiaryPaths.count) surface=\(inventory.surfacePresent)"
        return state
    }
}
