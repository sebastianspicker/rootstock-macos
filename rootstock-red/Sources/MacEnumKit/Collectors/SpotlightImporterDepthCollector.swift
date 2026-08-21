import Foundation
import RootstockCore

/// Spotlight importer residual depth (Wave-16).
/// Safety and behavior: path inventory only; never installs malicious Spotlight importers or dumps mdworker index contents.
public struct SpotlightImporterDepthCollector: Collector {
    public static let id = "collect.spotlight_importer_depth"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let inventory = PathPlaneInventorySupport.collect(
            spec: PathPlaneInventorySpec(
                primaryPaths: [
                    "/System/Library/Frameworks/CoreServices.framework/Frameworks/Metadata.framework",
                    "/usr/bin/mdimport",
                    "/usr/bin/mdfind",
                ],
                secondaryPaths: [
                    "/Library/Spotlight",
                    NSHomeDirectory() + "/Library/Spotlight",
                    "/System/Library/Spotlight",
                ],
                tertiaryPaths: [
                    "/System/Library/LaunchDaemons/com.apple.metadata.mds.plist",
                    "/System/Library/Frameworks/CoreSpotlight.framework",
                ],
                initialHonestyNote: "Spotlight importer depth: path presence only - never installs malicious Spotlight importers or dumps mdworker index contents"
            )
        )
        var state = CollectedState()
        state.spotlightImporterDepth = SpotlightImporterDepthState(
            metadataToolPaths: inventory.primaryPaths,
            spotlightImporterPaths: inventory.secondaryPaths,
            mdsLaunchPaths: inventory.tertiaryPaths,
            spotlightImporterSurfacePresent: inventory.surfacePresent,
            notes: inventory.notes
        )
        state.collectorNotes[Self.id] =
            "a=\(inventory.primaryPaths.count) b=\(inventory.secondaryPaths.count) c=\(inventory.tertiaryPaths.count) surface=\(inventory.surfacePresent)"
        return state
    }
}
