import Foundation
import RootstockCore

/// Notification Center residual depth (Wave-16).
/// Safety and behavior: path inventory only; never dumps notification body contents or forges notification payloads.
public struct NotificationCenterDepthCollector: Collector {
    public static let id = "collect.notification_center_depth"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let inventory = PathPlaneInventorySupport.collect(
            spec: PathPlaneInventorySpec(
                primaryPaths: [
                    "/System/Library/PrivateFrameworks/UserNotifications.framework",
                    "/System/Library/CoreServices/NotificationCenter.app",
                    "/usr/sbin/usernoted",
                ],
                secondaryPaths: [
                    NSHomeDirectory() + "/Library/Application Support/NotificationCenter",
                    NSHomeDirectory() + "/Library/Group Containers/group.com.apple.usernoted",
                ],
                tertiaryPaths: [
                    NSHomeDirectory() + "/Library/Preferences/com.apple.ncprefs.plist",
                    "/System/Library/LaunchAgents/com.apple.usernoted.plist",
                ],
                initialHonestyNote: "Notification Center depth: path presence only - never dumps notification body contents or forges notification payloads"
            )
        )
        var state = CollectedState()
        state.notificationCenterDepth = NotificationCenterDepthState(
            notificationFrameworkPaths: inventory.primaryPaths,
            notificationStorePaths: inventory.secondaryPaths,
            notificationPrefPaths: inventory.tertiaryPaths,
            notificationSurfacePresent: inventory.surfacePresent,
            notes: inventory.notes
        )
        state.collectorNotes[Self.id] =
            "a=\(inventory.primaryPaths.count) b=\(inventory.secondaryPaths.count) c=\(inventory.tertiaryPaths.count) surface=\(inventory.surfacePresent)"
        return state
    }
}
