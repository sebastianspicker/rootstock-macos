import Foundation
import RootstockCore

/// Software Update catalog residual surface (Wave-16).
/// Safety and behavior: path inventory only; never points SUS catalogs at attacker mirrors or tampers with update plists.
public struct SoftwareupdateCatalogCollector: Collector {
    public static let id = "collect.softwareupdate_catalog"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let inventory = PathPlaneInventorySupport.collect(
            spec: PathPlaneInventorySpec(
                primaryPaths: [
                    "/usr/sbin/softwareupdate",
                    "/System/Library/PrivateFrameworks/SoftwareUpdate.framework",
                    "/usr/libexec/softwareupdated",
                ],
                secondaryPaths: [
                    "/Library/Preferences/com.apple.SoftwareUpdate.plist",
                    "/Library/Preferences/com.apple.commerce.plist",
                ],
                tertiaryPaths: [
                    "/System/Library/LaunchDaemons/com.apple.softwareupdated.plist",
                    "/Library/Updates",
                ],
                initialHonestyNote: "Software Update catalog: path presence only - never points SUS catalogs at attacker mirrors or tampers with update plists"
            )
        )
        var state = CollectedState()
        state.softwareupdateCatalog = SoftwareupdateCatalogState(
            softwareUpdateToolPaths: inventory.primaryPaths,
            softwareUpdatePrefPaths: inventory.secondaryPaths,
            softwareUpdateDaemonPaths: inventory.tertiaryPaths,
            softwareUpdateSurfacePresent: inventory.surfacePresent,
            notes: inventory.notes
        )
        state.collectorNotes[Self.id] =
            "a=\(inventory.primaryPaths.count) b=\(inventory.secondaryPaths.count) c=\(inventory.tertiaryPaths.count) surface=\(inventory.surfacePresent)"
        return state
    }
}
