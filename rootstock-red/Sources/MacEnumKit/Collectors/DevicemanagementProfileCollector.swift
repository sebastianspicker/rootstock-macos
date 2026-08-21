import Foundation
import RootstockCore

/// Device management profile residual depth (Wave-16).
/// Safety and behavior: path inventory only; never installs configuration profiles or enrolls hosts in MDM.
public struct DevicemanagementProfileCollector: Collector {
    public static let id = "collect.devicemanagement_profile"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let inventory = PathPlaneInventorySupport.collect(
            spec: PathPlaneInventorySpec(
                primaryPaths: [
                    "/usr/bin/profiles",
                    "/System/Library/PrivateFrameworks/ConfigurationProfiles.framework",
                    "/usr/libexec/mdmclient",
                ],
                secondaryPaths: [
                    "/Library/Managed Preferences",
                    "/var/db/ConfigurationProfiles",
                    "/Library/ConfigurationProfiles",
                ],
                tertiaryPaths: [
                    "/System/Library/LaunchDaemons/com.apple.mdmclient.daemon.plist",
                    "/Library/Preferences/com.apple.mdmclient.plist",
                ],
                initialHonestyNote: "Device management profile: path presence only - never installs configuration profiles or enrolls hosts in MDM"
            )
        )
        var state = CollectedState()
        state.devicemanagementProfile = DevicemanagementProfileState(
            profilesToolPaths: inventory.primaryPaths,
            managedPrefPaths: inventory.secondaryPaths,
            mdmClientPaths: inventory.tertiaryPaths,
            deviceMgmtSurfacePresent: inventory.surfacePresent,
            notes: inventory.notes
        )
        state.collectorNotes[Self.id] =
            "a=\(inventory.primaryPaths.count) b=\(inventory.secondaryPaths.count) c=\(inventory.tertiaryPaths.count) surface=\(inventory.surfacePresent)"
        return state
    }
}
