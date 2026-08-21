import Foundation
import RootstockCore

/// Shortcuts iCloud sync residual depth (Wave-16).
/// Safety and behavior: path inventory only; never executes Shortcuts or dumps iCloud-synced automation databases.
public struct ShortcutsIcloudSyncCollector: Collector {
    public static let id = "collect.shortcuts_icloud_sync"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let inventory = PathPlaneInventorySupport.collect(
            spec: PathPlaneInventorySpec(
                primaryPaths: [
                    "/System/Applications/Shortcuts.app",
                    "/System/Library/PrivateFrameworks/WorkflowKit.framework",
                ],
                secondaryPaths: [
                    NSHomeDirectory() + "/Library/Shortcuts",
                    NSHomeDirectory() + "/Library/Group Containers/group.is.workflow.my.app",
                ],
                tertiaryPaths: [
                    NSHomeDirectory() + "/Library/Preferences/com.apple.shortcuts.plist",
                    "/System/Library/PrivateFrameworks/VoiceShortcutClient.framework",
                ],
                initialHonestyNote: "Shortcuts iCloud sync: path presence only - never executes Shortcuts or dumps iCloud-synced automation databases"
            )
        )
        var state = CollectedState()
        state.shortcutsIcloudSync = ShortcutsIcloudSyncState(
            shortcutsAppPaths: inventory.primaryPaths,
            shortcutsDbPaths: inventory.secondaryPaths,
            shortcutsPrefPaths: inventory.tertiaryPaths,
            shortcutsIcloudSurfacePresent: inventory.surfacePresent,
            notes: inventory.notes
        )
        state.collectorNotes[Self.id] =
            "a=\(inventory.primaryPaths.count) b=\(inventory.secondaryPaths.count) c=\(inventory.tertiaryPaths.count) surface=\(inventory.surfacePresent)"
        return state
    }
}
