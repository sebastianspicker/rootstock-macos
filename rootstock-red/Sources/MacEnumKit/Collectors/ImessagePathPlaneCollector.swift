import Foundation
import RootstockCore

/// iMessage / Messages path collection plane (Wave-16).
/// Safety and behavior: path inventory only; never reads Messages database contents or exports chat transcripts.
public struct ImessagePathPlaneCollector: Collector {
    public static let id = "collect.imessage_path_plane"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let inventory = PathPlaneInventorySupport.collect(
            spec: PathPlaneInventorySpec(
                primaryPaths: [
                    "/System/Applications/Messages.app",
                    "/Applications/Messages.app",
                    "/System/Library/PrivateFrameworks/IMCore.framework",
                ],
                secondaryPaths: [
                    NSHomeDirectory() + "/Library/Messages",
                    NSHomeDirectory() + "/Library/Messages/chat.db",
                    NSHomeDirectory() + "/Library/Containers/com.apple.iChat",
                ],
                tertiaryPaths: [
                    NSHomeDirectory() + "/Library/Preferences/com.apple.iChat.plist",
                    "/System/Library/PrivateFrameworks/IMFoundation.framework",
                ],
                initialHonestyNote: "iMessage path plane: path presence only - never reads Messages database contents or exports chat transcripts"
            )
        )
        var state = CollectedState()
        state.imessagePathPlane = ImessagePathPlaneState(
            messagesAppPaths: inventory.primaryPaths,
            messagesDbPaths: inventory.secondaryPaths,
            messagesPrefPaths: inventory.tertiaryPaths,
            imessageSurfacePresent: inventory.surfacePresent,
            notes: inventory.notes
        )
        state.collectorNotes[Self.id] =
            "a=\(inventory.primaryPaths.count) b=\(inventory.secondaryPaths.count) c=\(inventory.tertiaryPaths.count) surface=\(inventory.surfacePresent)"
        return state
    }
}
