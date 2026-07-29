import Foundation
import RootstockCore

/// LaunchAgents/Daemons (system) + BTM store presence + legacy login-item plist paths.
public struct LoginItemsBTMCollector: Collector {
    public static let id = "collect.loginitems_btm"
    public static let cost: CollectorCost = .medium

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let snapshot = discoverySnapshot()
        let loginItems = loginItems(from: snapshot)
        var state = CollectedState()
        state.systemLaunchAgents = snapshot.systemAgents
        state.launchDaemons = snapshot.daemons
        state.btmStorePresent = loginItems.btmStorePresent
        state.loginItemPaths = snapshot.loginPaths
        state.loginItems = loginItems
        state.collectorNotes[Self.id] = "systemAgents=\(snapshot.systemAgents.count) daemons=\(snapshot.daemons.count) btm=\(loginItems.btmStorePresent) loginPaths=\(snapshot.loginPaths.count)"
        return state
    }


    private struct DiscoverySnapshot {
        let systemAgents: [LaunchAgentEntry]
        let daemons: [LaunchAgentEntry]
        let btmDir: URL
        let btmDirExists: Bool
        let btmDirSize: Int64?
        let backgroundItemsURL: URL
        let backgroundItemsMeta: LaunchPlistSupport.FileMeta
        let loginPaths: [String]
        let notes: [String]
    }

    private func discoverySnapshot() -> DiscoverySnapshot {
        let fm = FileManager.default, home = fm.homeDirectoryForCurrentUser
        let systemAgents = LaunchPlistSupport.enumeratePlists(in: URL(fileURLWithPath: "/Library/LaunchAgents", isDirectory: true))
        let daemons = LaunchPlistSupport.enumeratePlists(in: URL(fileURLWithPath: "/Library/LaunchDaemons", isDirectory: true))
        let userAgents = LaunchPlistSupport.enumeratePlists(in: home.appendingPathComponent("Library/LaunchAgents", isDirectory: true))
        let btmDir = home.appendingPathComponent("Library/Application Support/com.apple.backgroundtaskmanagementagent", isDirectory: true)
        var isDir: ObjCBool = false
        let exists = fm.fileExists(atPath: btmDir.path, isDirectory: &isDir) && isDir.boolValue
        let backgroundItemsURL = btmDir.appendingPathComponent("backgrounditems.btm")
        let meta = LaunchPlistSupport.fileMeta(at: backgroundItemsURL.path)
        let systemNote = systemBTMNote()
        let paths = [home.appendingPathComponent("Library/Preferences/com.apple.loginitems.plist").path, home.appendingPathComponent("Library/Preferences/loginwindow.plist").path, backgroundItemsURL.path].filter { fm.fileExists(atPath: $0) }
        var notes = ["user LaunchAgents: \(userAgents.count) (also via PersistAudit)", "system LaunchAgents: \(systemAgents.count)", "LaunchDaemons: \(daemons.count)", systemNote, "BTM binary format not parsed (opaque evidence only)"]
        if meta.exists, let size = meta.size { notes.append("backgrounditems.btm size=\(size)") }
        return DiscoverySnapshot(systemAgents: systemAgents, daemons: daemons, btmDir: btmDir, btmDirExists: exists, btmDirSize: exists ? LaunchPlistSupport.directorySizeBytes(at: btmDir) : nil, backgroundItemsURL: backgroundItemsURL, backgroundItemsMeta: meta, loginPaths: paths, notes: notes)
    }

    private func systemBTMNote() -> String {
        let root = "/var/db/com.apple.backgroundtaskmanagement"
        guard FileManager.default.fileExists(atPath: root) else { return "system BTM path not present" }
        guard let items = try? FileManager.default.contentsOfDirectory(atPath: root) else { return "system BTM dir present but listing denied" }
        return "system BTM dir readable (\(items.count) entries, names only)"
    }

    private func loginItems(from snapshot: DiscoverySnapshot) -> LoginItemsState {
        LoginItemsState(btmStorePresent: snapshot.btmDirExists || snapshot.backgroundItemsMeta.exists, btmDirectoryPath: snapshot.btmDirExists ? snapshot.btmDir.path : nil, btmDirectorySizeBytes: snapshot.btmDirSize, backgroundItemsBtmPath: snapshot.backgroundItemsMeta.exists ? snapshot.backgroundItemsURL.path : nil, backgroundItemsBtmSizeBytes: snapshot.backgroundItemsMeta.size, loginItemPaths: snapshot.loginPaths, notes: snapshot.notes)
    }
}
