import Foundation
import RootstockCore

/// Handoff / Universal Clipboard residual depth (Wave-16).
/// Safety and behavior: path inventory only; never reads Universal Clipboard contents or forges Handoff activity.
public struct HandoffClipboardDepthCollector: Collector {
    public static let id = "collect.handoff_clipboard_depth"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let inventory = PathPlaneInventorySupport.collect(
            spec: PathPlaneInventorySpec(
                primaryPaths: [
                    "/System/Library/PrivateFrameworks/UserActivity.framework",
                    "/System/Library/PrivateFrameworks/ClipboardUI.framework",
                    "/usr/libexec/sharingd",
                ],
                secondaryPaths: [
                    NSHomeDirectory() + "/Library/Preferences/com.apple.coreservices.useractivityd.plist",
                    NSHomeDirectory() + "/Library/Caches/com.apple.Pasteboard",
                ],
                tertiaryPaths: [
                    "/System/Library/LaunchAgents/com.apple.sharingd.plist",
                    "/System/Library/PrivateFrameworks/Sharing.framework",
                ],
                initialHonestyNote: "Handoff clipboard depth: path presence only - never reads Universal Clipboard contents or forges Handoff activity"
            )
        )
        var state = CollectedState()
        state.handoffClipboardDepth = HandoffClipboardDepthState(
            handoffFrameworkPaths: inventory.primaryPaths,
            clipboardPathHits: inventory.secondaryPaths,
            sharingdPaths: inventory.tertiaryPaths,
            handoffSurfacePresent: inventory.surfacePresent,
            notes: inventory.notes
        )
        state.collectorNotes[Self.id] =
            "a=\(inventory.primaryPaths.count) b=\(inventory.secondaryPaths.count) c=\(inventory.tertiaryPaths.count) surface=\(inventory.surfacePresent)"
        return state
    }
}
