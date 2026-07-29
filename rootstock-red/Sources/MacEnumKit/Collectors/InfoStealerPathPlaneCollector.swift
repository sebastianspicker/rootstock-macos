import Foundation
import RootstockCore

/// Info-stealer multi-app collection path plane (Wave-9).
///
/// Research basis: AMOS/Atomic/Odyssey/PXA 2025–2026 infostealer collection themes (Microsoft/Red Canary).
/// Safety and behavior: typed multi-app path inventory beyond browser session alone; never dumps secrets.
public struct InfoStealerPathPlaneCollector: Collector {
    public static let id = "collect.infostealer_path_plane"
    public static let cost: CollectorCost = .low

    private static let browserAdjacent: [String] = [
        NSHomeDirectory() + "/Library/Application Support/Google/Chrome",
        NSHomeDirectory() + "/Library/Application Support/Google/Chrome/Default",
        NSHomeDirectory() + "/Library/Application Support/Firefox",
        NSHomeDirectory() + "/Library/Application Support/Firefox/Profiles",
        NSHomeDirectory() + "/Library/Application Support/Microsoft Edge",
        NSHomeDirectory() + "/Library/Safari",
        NSHomeDirectory() + "/Library/Cookies",
        NSHomeDirectory() + "/Library/Application Support/BraveSoftware/Brave-Browser",
    ]

    private static let messagingVault: [String] = [
        NSHomeDirectory() + "/Library/Messages",
        NSHomeDirectory() + "/Library/Mail",
        NSHomeDirectory() + "/Library/Group Containers/group.com.apple.notes",
        NSHomeDirectory() + "/Library/Containers/com.apple.Notes",
        NSHomeDirectory() + "/Library/Application Support/AddressBook",
        NSHomeDirectory() + "/Library/Keychains",
        NSHomeDirectory() + "/Library/Application Support/1Password",
        NSHomeDirectory() + "/Library/Application Support/com.1password.1password",
        NSHomeDirectory() + "/Library/Application Support/Bitwarden",
        NSHomeDirectory() + "/Library/Application Support/com.bitwarden.desktop",
        NSHomeDirectory() + "/Library/Application Support/KeePassXC",
        NSHomeDirectory() + "/Library/Application Support/Slack",
        NSHomeDirectory() + "/Library/Application Support/Telegram Desktop",
        NSHomeDirectory() + "/Library/Application Support/discord",
    ]

    private static let walletSync: [String] = [
        NSHomeDirectory() + "/Library/Application Support/Exodus",
        NSHomeDirectory() + "/Library/Application Support/Electrum",
        NSHomeDirectory() + "/Library/Application Support/Coinomi",
        NSHomeDirectory() + "/Library/Application Support/Ledger Live",
        NSHomeDirectory() + "/Library/CloudStorage",
        NSHomeDirectory() + "/Library/Mobile Documents",
        NSHomeDirectory() + "/Library/Application Support/Dropbox",
        NSHomeDirectory() + "/Dropbox",
        NSHomeDirectory() + "/Desktop",
        NSHomeDirectory() + "/Documents",
        NSHomeDirectory() + "/Downloads",
    ]

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = [
            "Info-stealer path plane: multi-app path presence only - never dumps cookies, passwords, keychains, or wallet material",
        ]

        var browser: [String] = []
        for path in Self.browserAdjacent where fm.fileExists(atPath: path) {
            browser.append(path)
            notes.append("browser_adjacent: \(path)")
        }

        var messaging: [String] = []
        for path in Self.messagingVault where fm.fileExists(atPath: path) {
            messaging.append(path)
            notes.append("messaging_or_vault: \(path)")
        }

        var wallet: [String] = []
        for path in Self.walletSync where fm.fileExists(atPath: path) {
            wallet.append(path)
            notes.append("wallet_or_sync: \(path)")
        }

        browser = Array(Set(browser)).sorted()
        messaging = Array(Set(messaging)).sorted()
        wallet = Array(Set(wallet)).sorted()

        let total = browser.count + messaging.count + wallet.count
        // Desktop/Documents/Downloads alone always exist - require multi-family or deeper hits.
        let surface =
            total >= 4
            || (browser.count >= 1 && messaging.count >= 1)
            || messaging.count >= 2

        var state = CollectedState()
        state.infoStealerPathPlane = InfoStealerPathPlaneState(
            browserAdjacentPaths: browser,
            messagingAndVaultPaths: messaging,
            walletAndSyncPaths: wallet,
            collectionSurfacePresent: surface,
            notes: notes
        )
        state.collectorNotes[Self.id] =
            "browser=\(browser.count) messagingVault=\(messaging.count) "
            + "walletSync=\(wallet.count) surface=\(surface)"
        return state
    }
}
