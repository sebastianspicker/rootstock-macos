import Foundation
import RootstockCore

/// Finder Sync extension dual-use surface (Wave-16).
/// Safety and behavior: path inventory only; never installs Finder Sync extensions or rewrites Finder preferences for abuse.
public struct FinderSyncExtensionCollector: Collector {
    public static let id = "collect.finder_sync_extension"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let inventory = PathPlaneInventorySupport.collect(
            spec: PathPlaneInventorySpec(
                primaryPaths: [
                    "/System/Library/Frameworks/FinderSync.framework",
                    "/System/Library/CoreServices/Finder.app",
                ],
                secondaryPaths: [
                    NSHomeDirectory() + "/Library/Application Scripts",
                    "/Library/Application Support",
                ],
                tertiaryPaths: [
                    NSHomeDirectory() + "/Library/Preferences/com.apple.finder.plist",
                    "/System/Library/PrivateFrameworks/FileProvider.framework",
                ],
                initialHonestyNote: "Finder Sync dual-use: path presence only - never installs Finder Sync extensions or rewrites Finder preferences for abuse"
            )
        )
        var state = CollectedState()
        state.finderSyncExtension = FinderSyncExtensionState(
            finderSyncFrameworkPaths: inventory.primaryPaths,
            appScriptPaths: inventory.secondaryPaths,
            finderPrefPaths: inventory.tertiaryPaths,
            finderSyncSurfacePresent: inventory.surfacePresent,
            notes: inventory.notes
        )
        state.collectorNotes[Self.id] =
            "a=\(inventory.primaryPaths.count) b=\(inventory.secondaryPaths.count) c=\(inventory.tertiaryPaths.count) surface=\(inventory.surfacePresent)"
        return state
    }
}
