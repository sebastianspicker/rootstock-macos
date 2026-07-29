import Foundation
import RootstockCore

/// Browser history DB path metadata only - never opens SQLite / reads rows / cookies / passwords.
public struct BrowserMetaCollector: Collector {
    public static let id = "collect.browser_meta"
    public static let cost: CollectorCost = .medium

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let home = FileManager.default.homeDirectoryForCurrentUser
        var entries = fixedEntries(for: home)
        entries.append(contentsOf: firefoxEntries(for: home))
        var state = CollectedState()
        state.browserMeta = entries
        let present = entries.filter(\.exists).count
        state.collectorNotes[Self.id] = "metadata only (\(present)/\(entries.count) present); no DB row reads"
        return state
    }


    private func fixedEntries(for home: URL) -> [BrowserMetaEntry] {
        [
            meta(browser: "Safari", kind: "history", path: home.appendingPathComponent("Library/Safari/History.db").path),
            meta(browser: "Chrome", kind: "history", path: home.appendingPathComponent("Library/Application Support/Google/Chrome/Default/History").path),
            meta(browser: "Edge", kind: "history", path: home.appendingPathComponent("Library/Application Support/Microsoft Edge/Default/History").path),
        ]
    }

    private func firefoxEntries(for home: URL) -> [BrowserMetaEntry] {
        let profilesRoot = home.appendingPathComponent("Library/Application Support/Firefox/Profiles", isDirectory: true)
        guard let profiles = try? FileManager.default.contentsOfDirectory(at: profilesRoot, includingPropertiesForKeys: nil, options: [.skipsHiddenFiles]) else {
            return [BrowserMetaEntry(browser: "Firefox", kind: "history", path: profilesRoot.appendingPathComponent("<profile>/places.sqlite").path, exists: false)]
        }
        return profiles.sorted { $0.path < $1.path }.prefix(8).map {
            meta(browser: "Firefox", kind: "history", path: $0.appendingPathComponent("places.sqlite").path)
        }
    }

    private func meta(browser: String, kind: String, path: String) -> BrowserMetaEntry {
        let m = LaunchPlistSupport.fileMeta(at: path)
        return BrowserMetaEntry(
            browser: browser,
            kind: kind,
            path: path,
            exists: m.exists,
            sizeBytes: m.size,
            modifiedAt: m.mtime
        )
    }
}
