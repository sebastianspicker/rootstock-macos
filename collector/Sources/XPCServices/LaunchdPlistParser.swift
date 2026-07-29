import Foundation
import RootstockMacFacts

/// Parses launchd plist files (XML and binary) from LaunchDaemon/LaunchAgent directories.
///
/// Directory listing and Program/ProgramArguments/KeepAlive extraction use
/// `LaunchdPlistFacts` (RootstockMacFacts). Product-specific fields (MachServices,
/// SMAuthorizedClients, required Label) stay here.
public struct LaunchdPlistParser {

    public struct ParsedEntry {
        public let label: String
        public let plistPath: String
        public let program: String?
        public let user: String?
        public let runAtLoad: Bool
        public let keepAlive: Bool
        public let machServices: [String]
        public let hasAuthorizedClients: Bool
    }

    public init() {}

    /// Parse a single plist file. Returns nil if the file is missing, unreadable, or malformed.
    public func parse(at path: String) -> ParsedEntry? {
        guard let data = FileManager.default.contents(atPath: path) else { return nil }

        var format = PropertyListSerialization.PropertyListFormat.xml
        guard let plist = try? PropertyListSerialization.propertyList(
            from: data, options: [], format: &format
        ) as? [String: Any] else { return nil }

        let shared = LaunchdPlistFacts.summarize(path: path, dict: plist)
        guard let label = shared.label, !label.isEmpty else { return nil }

        // MachServices is a dict; we want the registered service name keys
        let machServices: [String]
        if let services = plist["MachServices"] as? [String: Any] {
            machServices = Array(services.keys).sorted()
        } else {
            machServices = []
        }

        // SMAuthorizedClients is an array of code signing requirement strings
        let hasAuthorizedClients: Bool
        if let clients = plist["SMAuthorizedClients"] as? [String] {
            hasAuthorizedClients = !clients.isEmpty
        } else {
            hasAuthorizedClients = false
        }

        return ParsedEntry(
            label: label,
            plistPath: path,
            program: shared.program,
            user: shared.userName,
            runAtLoad: shared.runAtLoad,
            keepAlive: shared.keepAlive,
            machServices: machServices,
            hasAuthorizedClients: hasAuthorizedClients
        )
    }

    /// Parse all plists in a directory. Missing directories are silently skipped.
    /// Returns (entries, errorMessages) - never throws.
    public func parseDirectory(at dirPath: String) -> (entries: [ParsedEntry], errors: [String]) {
        let fm = FileManager.default

        guard fm.fileExists(atPath: dirPath) else {
            // Non-existent directories are normal (e.g., ~/Library/LaunchAgents)
            return ([], [])
        }

        let paths = LaunchdPlistFacts.listPlistPaths(in: dirPath, fileManager: fm)
        // Distinguish unreadable directory (exists but list fails) from empty
        if paths.isEmpty, (try? fm.contentsOfDirectory(atPath: dirPath)) == nil {
            return ([], ["Cannot read directory: \(dirPath)"])
        }

        var entries: [ParsedEntry] = []
        var errors: [String] = []

        for fullPath in paths {
            if let entry = parse(at: fullPath) {
                entries.append(entry)
            } else {
                errors.append("Skipped unparseable plist: \(fullPath)")
            }
        }

        return (entries, errors)
    }
}
