import Foundation

/// Parses launchd plist files (XML and binary) from LaunchDaemon/LaunchAgent directories.
///
/// PropertyListSerialization handles both XML and binary plist formats transparently.
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

        guard let label = plist["Label"] as? String, !label.isEmpty else { return nil }

        // Binary path from Program or first element of ProgramArguments
        let program: String?
        if let prog = plist["Program"] as? String {
            program = prog
        } else if let args = plist["ProgramArguments"] as? [String], let first = args.first {
            program = first
        } else {
            program = nil
        }

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
            program: program,
            user: plist["UserName"] as? String,
            runAtLoad: plist["RunAtLoad"] as? Bool ?? false,
            keepAlive: resolveKeepAlive(plist["KeepAlive"]),
            machServices: machServices,
            hasAuthorizedClients: hasAuthorizedClients
        )
    }

    /// Parse all plists in a directory. Missing directories are silently skipped.
    /// Returns (entries, errorMessages) — never throws.
    public func parseDirectory(at dirPath: String) -> (entries: [ParsedEntry], errors: [String]) {
        let fm = FileManager.default

        guard fm.fileExists(atPath: dirPath) else {
            // Non-existent directories are normal (e.g., ~/Library/LaunchAgents)
            return ([], [])
        }

        guard let filenames = try? fm.contentsOfDirectory(atPath: dirPath) else {
            return ([], ["Cannot read directory: \(dirPath)"])
        }

        var entries: [ParsedEntry] = []
        var errors: [String] = []

        for filename in filenames where filename.hasSuffix(".plist") {
            let fullPath = (dirPath as NSString).appendingPathComponent(filename)
            if let entry = parse(at: fullPath) {
                entries.append(entry)
            } else {
                errors.append("Skipped unparseable plist: \(fullPath)")
            }
        }

        return (entries, errors)
    }

    // MARK: - Private

    /// KeepAlive can be a plain Bool or a throttle-config dict (non-empty dict = true).
    private func resolveKeepAlive(_ value: Any?) -> Bool {
        if let b = value as? Bool { return b }
        if let d = value as? [String: Any], !d.isEmpty { return true }
        return false
    }
}
