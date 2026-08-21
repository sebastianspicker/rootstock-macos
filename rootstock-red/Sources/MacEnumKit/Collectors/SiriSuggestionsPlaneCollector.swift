import Foundation
import RootstockCore

/// Siri / Suggestions data-access residual (Wave-16).
/// Safety and behavior: path inventory only; never dumps Siri transcripts or Suggestions databases contents.
public struct SiriSuggestionsPlaneCollector: Collector {
    public static let id = "collect.siri_suggestions_plane"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let inventory = PathPlaneInventorySupport.collect(
            spec: PathPlaneInventorySpec(
                primaryPaths: [
                    "/System/Library/PrivateFrameworks/AssistantServices.framework",
                    "/System/Library/PrivateFrameworks/SiriUI.framework",
                    "/System/Library/CoreServices/Siri.app",
                ],
                secondaryPaths: [
                    NSHomeDirectory() + "/Library/Assistant",
                    NSHomeDirectory() + "/Library/Suggestions",
                    NSHomeDirectory() + "/Library/DuetExpertCenter",
                ],
                tertiaryPaths: [
                    NSHomeDirectory() + "/Library/Preferences/com.apple.assistant.plist",
                    "/System/Library/LaunchAgents/com.apple.assistantd.plist",
                ],
                initialHonestyNote: "Siri Suggestions residual: path presence only - never dumps Siri transcripts or Suggestions databases contents"
            )
        )
        var state = CollectedState()
        state.siriSuggestionsPlane = SiriSuggestionsPlaneState(
            siriFrameworkPaths: inventory.primaryPaths,
            suggestionsStorePaths: inventory.secondaryPaths,
            siriPrefPaths: inventory.tertiaryPaths,
            siriSurfacePresent: inventory.surfacePresent,
            notes: inventory.notes
        )
        state.collectorNotes[Self.id] =
            "a=\(inventory.primaryPaths.count) b=\(inventory.secondaryPaths.count) c=\(inventory.tertiaryPaths.count) surface=\(inventory.surfacePresent)"
        return state
    }
}
