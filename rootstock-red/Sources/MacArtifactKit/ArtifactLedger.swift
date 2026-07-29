import Foundation
import RootstockCore

/// Tracks filesystem artifacts touched during assessment.
///
/// Actor-isolated so concurrent collectors/checks can record safely without
/// `@unchecked Sendable` or manual locking.
public actor ArtifactLedger {
    private var records: [ArtifactRecord] = []

    public init() {}

    public func record(
        path: String,
        action: String,
        hash: String? = nil,
        cleanupRecipe: String? = nil
    ) {
        let entry = ArtifactRecord(
            path: path,
            action: action,
            hash: hash,
            cleanupRecipe: cleanupRecipe
        )
        records.append(entry)
    }

    public func allRecords() -> [ArtifactRecord] {
        records
    }

    /// Record observable paths from a completed collection snapshot.
    ///
    /// Only records paths that were inventoried (and, where applicable, present/exists).
    /// Does not create or mutate host files.
    public func recordStatePaths(_ state: CollectedState) {
        record(paths: state.launchAgents.map(\.path), action: "observe.launchAgent")
        record(paths: state.systemLaunchAgents.map(\.path), action: "observe.systemLaunchAgent")
        record(paths: state.launchDaemons.map(\.path), action: "observe.launchDaemon")
        record(paths: state.browserMeta.filter(\.exists).map(\.path), action: "observe.browserMeta")
        record(paths: state.credPaths.filter(\.exists).map(\.path), action: "observe.credPath")
        record(paths: state.securityProducts.filter(\.present).map(\.path), action: "observe.securityProduct")
        record(paths: state.loobins.filter(\.present).map(\.path), action: "observe.loobin")
        record(paths: state.codesignSamples.map(\.path), action: "observe.codesign")
        record(paths: state.injectabilityHits.map(\.path), action: "observe.injectability")
        record(paths: state.dylibRiskHits.map(\.path), action: "observe.dylibRisk")
        record(paths: state.privilegedHelperTools, action: "observe.privilegedHelper")
        record(paths: state.systemExtensionPaths, action: "observe.systemExtension")
        record(paths: state.loginItemPaths, action: "observe.loginItem")
        recordLoginItems(state.loginItems)
        recordTCCPaths(state.tcc)
    }

    public func exportJSON() throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return try encoder.encode(allRecords())
    }

    public func write(to url: URL) throws {
        try exportJSON().write(to: url, options: .atomic)
    }

    // MARK: - Helpers

    private func record(paths: [String], action: String) {
        for path in paths {
            record(path: path, action: action)
        }
    }

    private func recordLoginItems(_ loginItems: LoginItemsState?) {
        guard let loginItems else { return }
        let btmPaths = [loginItems.btmDirectoryPath, loginItems.backgroundItemsBtmPath].compactMap { $0 }
        record(paths: btmPaths, action: "observe.btm")
        record(paths: loginItems.loginItemPaths, action: "observe.loginItem")
    }

    private func recordTCCPaths(_ tcc: TCCState?) {
        guard let tcc else { return }
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let userDatabase = (home as NSString).appendingPathComponent(
            "Library/Application Support/com.apple.TCC/TCC.db"
        )
        record(paths: [userDatabase, "/Library/Application Support/com.apple.TCC/TCC.db"], action: "observe.tcc")
        record(paths: tcc.notes.compactMap(Self.pathFromNote), action: "observe.tccNote")
    }

    private static func pathFromNote(_ note: String) -> String? {
        // Prefer explicit path= fragments from collectors.
        if let range = note.range(of: "path=") {
            let rest = note[range.upperBound...]
            let token = rest.split(whereSeparator: { $0.isWhitespace }).first.map(String.init)
            if let token, token.hasPrefix("/") {
                return token
            }
        }
        // Bare absolute path line endings (e.g. "… /Users/…/TCC.db").
        let parts = note.split(whereSeparator: { $0.isWhitespace }).map(String.init)
        if let last = parts.last, last.hasPrefix("/"), last.contains("/") {
            return last
        }
        return nil
    }
}
