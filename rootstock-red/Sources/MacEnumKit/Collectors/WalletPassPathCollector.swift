import Foundation
import RootstockCore

/// Wallet / pass residual path plane (Wave-16).
/// Safety and behavior: path inventory only; never dumps pass contents, payment tokens, or card data.
public struct WalletPassPathCollector: Collector {
    public static let id = "collect.wallet_pass_path"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let inventory = PathPlaneInventorySupport.collect(
            spec: PathPlaneInventorySpec(
                primaryPaths: [
                    "/System/Applications/Wallet.app",
                    "/System/Library/Frameworks/PassKit.framework",
                    "/usr/libexec/passd",
                ],
                secondaryPaths: [
                    NSHomeDirectory() + "/Library/Passes",
                    NSHomeDirectory() + "/Library/Containers/com.apple.Passbook",
                ],
                tertiaryPaths: [
                    NSHomeDirectory() + "/Library/Preferences/com.apple.Passbook.plist",
                    "/System/Library/PrivateFrameworks/PassKitCore.framework",
                ],
                initialHonestyNote: "Wallet pass path: path presence only - never dumps pass contents, payment tokens, or card data"
            )
        )
        var state = CollectedState()
        state.walletPassPath = WalletPassPathState(
            walletAppPaths: inventory.primaryPaths,
            passesStorePaths: inventory.secondaryPaths,
            passdPaths: inventory.tertiaryPaths,
            walletSurfacePresent: inventory.surfacePresent,
            notes: inventory.notes
        )
        state.collectorNotes[Self.id] =
            "a=\(inventory.primaryPaths.count) b=\(inventory.secondaryPaths.count) c=\(inventory.tertiaryPaths.count) surface=\(inventory.surfacePresent)"
        return state
    }
}
