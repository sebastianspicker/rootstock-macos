import Foundation
import RootstockCore

/// File Provider domain residual surface (Wave-16).
/// Safety and behavior: path inventory only; never registers malicious File Provider domains or exfiltrates provider caches.
public struct FileproviderDomainCollector: Collector {
    public static let id = "collect.fileprovider_domain"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let inventory = PathPlaneInventorySupport.collect(
            spec: PathPlaneInventorySpec(
                primaryPaths: [
                    "/System/Library/Frameworks/FileProvider.framework",
                    "/System/Library/PrivateFrameworks/FileProviderDaemon.framework",
                    "/usr/libexec/fileproviderd",
                ],
                secondaryPaths: [
                    NSHomeDirectory() + "/Library/Application Support/FileProvider",
                    NSHomeDirectory() + "/Library/CloudStorage",
                ],
                tertiaryPaths: [
                    "/System/Library/LaunchAgents/com.apple.FileProvider.plist",
                    NSHomeDirectory() + "/Library/Preferences/com.apple.FileProvider.plist",
                ],
                initialHonestyNote: "File Provider domain: path presence only - never registers malicious File Provider domains or exfiltrates provider caches"
            )
        )
        var state = CollectedState()
        state.fileproviderDomain = FileproviderDomainState(
            fileProviderFrameworkPaths: inventory.primaryPaths,
            cloudStoragePaths: inventory.secondaryPaths,
            fileProviderLaunchPaths: inventory.tertiaryPaths,
            fileProviderSurfacePresent: inventory.surfacePresent,
            notes: inventory.notes
        )
        state.collectorNotes[Self.id] =
            "a=\(inventory.primaryPaths.count) b=\(inventory.secondaryPaths.count) c=\(inventory.tertiaryPaths.count) surface=\(inventory.surfacePresent)"
        return state
    }
}
