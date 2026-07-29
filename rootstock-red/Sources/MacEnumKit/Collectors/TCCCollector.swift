import Foundation
import CoreServices
import RootstockCore
import RootstockMacFacts

/// Non-prompting TCC / FDA heuristics (assess-safe).
///
/// Strategy:
/// - Prefer `isReadableFile` / existence checks (typically no TCC prompt).
/// - Directory listability on Desktop/Documents/Downloads uses `contentsOfDirectory`
///   which may inherit the host process's existing Files-and-Folders grants; we do not
///   open panels, touch Keychain, or request new TCC prompts intentionally.
/// - System TCC.db readability is a strong FDA signal when true.
/// - Optional CoreServices `MDItemCreateWithURL` metadata peek (no UI) for Library files.
public struct TCCCollector: Collector {
    public static let id = "collect.tcc_graph"
    public static let cost: CollectorCost = .medium

    public init() {}

    private struct TCCDatabaseSignals {
        let userReadable: Bool
        let systemReadable: Bool
        let paths: [String]
    }

    private struct FoldersProbe {
        let listable: [String]
        let unlistable: [String]
        let paths: [String]
    }

    private struct FDASensitiveProbe {
        let readableHits: Int
        let deniedHits: Int
        let missingHits: Int
        let paths: [String]
    }

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        let home = fm.homeDirectoryForCurrentUser

        var notes: [String] = [
            "Non-prompting FDA/TCC heuristics only - no UI, no Keychain, no TCC.db content read",
        ]
        let databases = Self.tccDatabaseSignals(fileManager: fm, home: home, notes: &notes)
        let folders = Self.folderListability(fileManager: fm, home: home, notes: &notes)
        let fda = Self.fdaSensitivePaths(fileManager: fm, home: home, notes: &notes)

        // MARK: Spotlight MDItem attribute peek (no UI, no query window)
        let mdProbe = Self.spotlightMDItemProbe(home: home, fm: fm)
        notes.append(contentsOf: mdProbe.notes)
        let pathsTouched = databases.paths + folders.paths + fda.paths + mdProbe.paths

        // MARK: Aggregate FDA likelihood
        let fullDiskAccessLikely = Self.fullDiskAccessLikelihood(
            databases: databases,
            fda: fda,
            notes: &notes
        )

        notes.append(
            "Files-and-Folders listable: \(folders.listable.joined(separator: ",").ifEmpty("none")); not: \(folders.unlistable.joined(separator: ",").ifEmpty("none"))"
        )
        notes.append(
            "pathsTouched count=\(Set(pathsTouched).count) (for artifact ledger notes)"
        )

        let probeMethod =
            "tcc_db_readable+desktop_docs_downloads_listability+fda_sensitive_paths(calendars,reminders,containers)+mditem_spotlight_attrs"

        var state = CollectedState()
        state.tcc = TCCState(
            fullDiskAccessLikely: fullDiskAccessLikely,
            notes: notes,
            probeMethod: probeMethod
        )
        state.collectorNotes[Self.id] =
            "FDA likely=\(fullDiskAccessLikely.map(String.init(describing:)) ?? "nil"); method=\(probeMethod)"
        return state
    }

    // MARK: - Helpers

    private enum ListResult {
        case listable(count: Int)
        case notListable(reason: String)
        case missing
    }

    private static func tccDatabaseSignals(
        fileManager: FileManager,
        home: URL,
        notes: inout [String]
    ) -> TCCDatabaseSignals {
        let userDatabase = MacSecurityPaths.userTCCDatabase(home: home)
        let systemDatabase = URL(fileURLWithPath: MacSecurityPaths.systemTCCDatabase)
        let userExists = fileManager.fileExists(atPath: userDatabase.path)
        let userReadable = fileManager.isReadableFile(atPath: userDatabase.path)
        let systemExists = fileManager.fileExists(atPath: systemDatabase.path)
        let systemReadable = fileManager.isReadableFile(atPath: systemDatabase.path)
        notes.append("User TCC.db exists=\(userExists) readable=\(userReadable) path=\(userDatabase.path)")
        notes.append("System TCC.db exists=\(systemExists) readable=\(systemReadable) path=\(systemDatabase.path)")
        return TCCDatabaseSignals(
            userReadable: userReadable,
            systemReadable: systemReadable,
            paths: [userDatabase.path, systemDatabase.path]
        )
    }

    private static func folderListability(
        fileManager: FileManager,
        home: URL,
        notes: inout [String]
    ) -> FoldersProbe {
        let probes = ["Desktop", "Documents", "Downloads"].map {
            ($0, home.appendingPathComponent($0))
        }
        var listable: [String] = []
        var unlistable: [String] = []
        for (name, url) in probes {
            switch listability(of: url, fm: fileManager) {
            case .listable(let count):
                listable.append(name)
                notes.append("\(name): listable (entries≈\(count))")
            case .notListable(let reason):
                unlistable.append(name)
                notes.append("\(name): not listable (\(reason))")
            case .missing:
                notes.append("\(name): path missing")
            }
        }
        return FoldersProbe(listable: listable, unlistable: unlistable, paths: probes.map { $0.1.path })
    }

    private static func fdaSensitivePaths(
        fileManager: FileManager,
        home: URL,
        notes: inout [String]
    ) -> FDASensitiveProbe {
        let probes = [
            ("Safari History.db", "Library/Safari/History.db"), ("Mail", "Library/Mail"),
            ("Messages chat.db", "Library/Messages/chat.db"), ("Cookies", "Library/Cookies"),
            ("Knowledge", "Library/Application Support/Knowledge"),
            ("CallHistoryDB", "Library/Application Support/CallHistoryDB"),
            ("Calendars", "Library/Calendars"), ("Reminders", "Library/Reminders"),
            ("Accounts", "Library/Accounts"), ("Containers meta", "Library/Containers"),
            ("Group Containers", "Library/Group Containers"), ("Suggestions", "Library/Suggestions"),
            ("Metadata", "Library/Metadata"),
        ].map { ($0.0, home.appendingPathComponent($0.1)) }
        var readable = 0
        var denied = 0
        var missing = 0
        for (label, url) in probes {
            let result = fdaReadability(of: url, fileManager: fileManager)
            switch result {
            case .readable:
                readable += 1
                notes.append("FDA-sensitive \(label): readable path=\(url.path)")
            case .listable:
                readable += 1
                notes.append("FDA-sensitive \(label): listable path=\(url.path)")
            case .denied(let reason):
                denied += 1
                notes.append("FDA-sensitive \(label): \(reason) path=\(url.path)")
            case .missing:
                missing += 1
                notes.append("FDA-sensitive \(label): missing path=\(url.path)")
            }
        }
        return FDASensitiveProbe(
            readableHits: readable,
            deniedHits: denied,
            missingHits: missing,
            paths: probes.map { $0.1.path }
        )
    }

    private enum FDAReadability {
        case readable
        case listable
        case denied(String)
        case missing
    }

    private static func fdaReadability(of url: URL, fileManager: FileManager) -> FDAReadability {
        guard fileManager.fileExists(atPath: url.path) else { return .missing }
        guard fileManager.isReadableFile(atPath: url.path) else {
            return .denied("exists but not readable")
        }
        var isDirectory: ObjCBool = false
        guard fileManager.fileExists(atPath: url.path, isDirectory: &isDirectory), isDirectory.boolValue else {
            return .readable
        }
        switch listability(of: url, fm: fileManager) {
        case .listable:
            return .listable
        case .notListable(let reason):
            return .denied("dir not listable (\(reason))")
        case .missing:
            return .missing
        }
    }

    private static func fullDiskAccessLikelihood(
        databases: TCCDatabaseSignals,
        fda: FDASensitiveProbe,
        notes: inout [String]
    ) -> Bool? {
        if databases.systemReadable || fda.readableHits >= 2 {
            notes.append("FDA likely=true (systemTCCReadable=\(databases.systemReadable), fdaReadableHits=\(fda.readableHits))")
            return true
        }
        if databases.userReadable {
            notes.append("FDA likely=true (user TCC.db unexpectedly readable)")
            return true
        }
        if fda.deniedHits >= 2 && !databases.systemReadable {
            notes.append("FDA likely=false (fdaDeniedHits=\(fda.deniedHits), system TCC not readable)")
            return false
        }
        notes.append("FDA likely=unknown (insufficient signal; denied=\(fda.deniedHits) readable=\(fda.readableHits) missing=\(fda.missingHits))")
        return nil
    }

    private static func listability(of url: URL, fm: FileManager) -> ListResult {
        var isDir: ObjCBool = false
        guard fm.fileExists(atPath: url.path, isDirectory: &isDir) else {
            return .missing
        }
        do {
            let items = try fm.contentsOfDirectory(
                at: url,
                includingPropertiesForKeys: nil,
                options: [.skipsHiddenFiles]
            )
            return .listable(count: items.count)
        } catch {
            let ns = error as NSError
            // Cocoa error 257 / POSIX EPERM/EACCES - permission without inventing a prompt.
            return .notListable(reason: "\(ns.domain)#\(ns.code): \(error.localizedDescription)")
        }
    }

    /// Non-prompting Spotlight metadata via `MDItemCreateWithURL` for a single home Library file.
    private static func spotlightMDItemProbe(
        home: URL,
        fm: FileManager
    ) -> (notes: [String], paths: [String]) {
        var notes: [String] = []
        var paths: [String] = []

        // Prefer a near-universal prefs file; fall back to a few candidates.
        let candidates: [URL] = [
            home.appendingPathComponent("Library/Preferences/.GlobalPreferences.plist"),
            home.appendingPathComponent("Library/Preferences/com.apple.finder.plist"),
            home.appendingPathComponent("Library/Preferences/com.apple.dock.plist"),
        ]

        guard let target = candidates.first(where: { fm.fileExists(atPath: $0.path) }) else {
            notes.append("Spotlight MDItem: no candidate Library prefs file found")
            return (notes, paths)
        }
        paths.append(target.path)

        // MDItemCreateWithURL does not present UI; attribute copy is local metadata.
        guard let item = MDItemCreateWithURL(kCFAllocatorDefault, target as CFURL) else {
            notes.append(
                "Spotlight MDItem: MDItemCreateWithURL returned nil path=\(target.path)"
            )
            return (notes, paths)
        }

        var attrCount = 0
        if let names = MDItemCopyAttributeNames(item) as? [String] {
            attrCount = names.count
        }

        var displayName: String?
        if let name = MDItemCopyAttribute(item, kMDItemDisplayName) as? String {
            displayName = name
        }
        var contentType: String?
        if let ct = MDItemCopyAttribute(item, kMDItemContentType) as? String {
            contentType = ct
        }

        notes.append(
            "Spotlight MDItem: ok attrs≈\(attrCount) displayName=\(displayName ?? "nil") contentType=\(contentType ?? "nil") path=\(target.path)"
        )
        return (notes, paths)
    }
}

private extension String {
    func ifEmpty(_ fallback: String) -> String {
        isEmpty ? fallback : self
    }
}
