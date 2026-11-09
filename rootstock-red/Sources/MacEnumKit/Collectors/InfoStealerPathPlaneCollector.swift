import Foundation
import RootstockCore

/// Info-stealer multi-app collection path plane.
///
/// Research basis: AMOS/Atomic/Odyssey/PXA 2025–2026 infostealer collection themes (Microsoft/Red Canary).
/// Safety and behavior: typed multi-app path inventory beyond browser session alone; never dumps secrets.
public struct InfoStealerPathPlaneCollector: Collector {
    public static let id = "collect.infostealer_path_plane"
    public static let cost: CollectorCost = .low

    private static let browserAdjacent: [String] = [
        AssessedHome.path + "/Library/Application Support/Google/Chrome",
        AssessedHome.path + "/Library/Application Support/Google/Chrome/Default",
        AssessedHome.path + "/Library/Application Support/Firefox",
        AssessedHome.path + "/Library/Application Support/Firefox/Profiles",
        AssessedHome.path + "/Library/Application Support/Microsoft Edge",
        AssessedHome.path + "/Library/Safari",
        AssessedHome.path + "/Library/Cookies",
        AssessedHome.path + "/Library/Application Support/BraveSoftware/Brave-Browser",
    ]

    private static let messagingVault: [String] = [
        AssessedHome.path + "/Library/Messages",
        AssessedHome.path + "/Library/Mail",
        AssessedHome.path + "/Library/Group Containers/group.com.apple.notes",
        AssessedHome.path + "/Library/Containers/com.apple.Notes",
        AssessedHome.path + "/Library/Application Support/AddressBook",
        AssessedHome.path + "/Library/Keychains",
        AssessedHome.path + "/Library/Application Support/1Password",
        AssessedHome.path + "/Library/Application Support/com.1password.1password",
        AssessedHome.path + "/Library/Application Support/Bitwarden",
        AssessedHome.path + "/Library/Application Support/com.bitwarden.desktop",
        AssessedHome.path + "/Library/Application Support/KeePassXC",
        AssessedHome.path + "/Library/Application Support/Slack",
        AssessedHome.path + "/Library/Application Support/Telegram Desktop",
        AssessedHome.path + "/Library/Application Support/discord",
    ]

    private static let walletSync: [String] = [
        AssessedHome.path + "/Library/Application Support/Exodus",
        AssessedHome.path + "/Library/Application Support/Electrum",
        AssessedHome.path + "/Library/Application Support/Coinomi",
        AssessedHome.path + "/Library/Application Support/Ledger Live",
        AssessedHome.path + "/Library/CloudStorage",
        AssessedHome.path + "/Library/Mobile Documents",
        AssessedHome.path + "/Library/Application Support/Dropbox",
        AssessedHome.path + "/Dropbox",
        AssessedHome.path + "/Desktop",
        AssessedHome.path + "/Documents",
        AssessedHome.path + "/Downloads",
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
