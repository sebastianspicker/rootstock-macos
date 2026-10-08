import Foundation
import HostCommand
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
        /// `ProgramArguments` with secret-looking values redacted, capped at `maxArguments`
        /// entries of `maxArgumentLength` characters.
        public let programArguments: [String]
        /// Sorted `EnvironmentVariables` keys (values are not kept).
        public let environmentVariableNames: [String]
        /// `EnvironmentVariables` entries whose key starts with `DYLD_`.
        public let dyldEnvironment: [String: String]
        /// Sorted launch triggers derived from key presence (see `triggerKeys`).
        public let triggers: [String]
        public let intervalSeconds: Int?
        public let sessionType: String?
        public let disabled: Bool
        /// ISO 8601 UTC modification time of the plist file.
        public let plistModified: String?
        /// `BundleProgram`: an SMAppService job's program, relative to its app bundle root.
        public let bundleProgram: String?

        /// The same entry with `program` resolved from `BundleProgram` against the app bundle
        /// that embeds the plist. Entries that already name a program are returned unchanged.
        public func resolvingBundleProgram(in bundlePath: String) -> ParsedEntry {
            guard program == nil, let relative = bundleProgram, LaunchdPlistParser.staysInsideBundle(relative) else {
                return self
            }
            let resolved = (bundlePath as NSString).appendingPathComponent(relative)
            return ParsedEntry(
                label: label, plistPath: plistPath, program: resolved, user: user,
                runAtLoad: runAtLoad, keepAlive: keepAlive, machServices: machServices,
                hasAuthorizedClients: hasAuthorizedClients, programArguments: programArguments,
                environmentVariableNames: environmentVariableNames, dyldEnvironment: dyldEnvironment,
                triggers: triggers, intervalSeconds: intervalSeconds, sessionType: sessionType,
                disabled: disabled, plistModified: plistModified, bundleProgram: bundleProgram
            )
        }
    }

    /// A `BundleProgram` value is a relative path; absolute paths, `..` components and NUL
    /// bytes could point outside the app bundle and are ignored.
    static func staysInsideBundle(_ relative: String) -> Bool {
        guard !relative.isEmpty, !relative.hasPrefix("/"), !relative.contains("\0") else { return false }
        return relative.split(separator: "/").allSatisfy { $0 != ".." }
    }

    public static let maxArguments = 16
    public static let maxArgumentLength = 256

    /// Plist keys whose presence makes launchd start the job, mapped to trigger names.
    static let triggerKeys: [String: String] = [
        "StartInterval": "start_interval",
        "StartCalendarInterval": "start_calendar_interval",
        "WatchPaths": "watch_paths",
        "QueueDirectories": "queue_directories",
        "Sockets": "sockets",
        "MachServices": "mach_services",
        "LaunchEvents": "launch_events",
        "inetdCompatibility": "inetd_compatibility",
    ]

    public init() {}

    /// Parse a single plist file. Returns nil if the file is missing, unreadable, or malformed.
    public func parse(at path: String) -> ParsedEntry? {
        guard let data = try? BoundedFileReader.read(path: path) else { return nil }

        var format = PropertyListSerialization.PropertyListFormat.xml
        guard let plist = try? PropertyListSerialization.propertyList(
            from: data, options: [], format: &format
        ) as? [String: Any] else { return nil }

        return parse(dict: plist, path: path, plistModified: FileTimestamp.modified(path: path))
    }

    /// Build an entry from an already-loaded plist dictionary. Returns nil without a Label.
    public func parse(dict plist: [String: Any], path: String, plistModified: String? = nil) -> ParsedEntry? {
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

        let environment = plist["EnvironmentVariables"] as? [String: Any] ?? [:]
        return ParsedEntry(
            label: label,
            plistPath: path,
            program: shared.program,
            user: shared.userName,
            runAtLoad: shared.runAtLoad,
            keepAlive: shared.keepAlive,
            machServices: machServices,
            hasAuthorizedClients: hasAuthorizedClients,
            programArguments: Self.cappedArguments(shared.programArguments),
            environmentVariableNames: environment.keys.sorted(),
            dyldEnvironment: Self.dyldEnvironment(environment),
            triggers: Self.triggers(in: plist),
            intervalSeconds: plist["StartInterval"] as? Int,
            sessionType: Self.sessionType(plist["LimitLoadToSessionType"]),
            disabled: plist["Disabled"] as? Bool ?? false,
            plistModified: plistModified,
            bundleProgram: (plist["BundleProgram"] as? String).flatMap { $0.isEmpty ? nil : $0 }
        )
    }

    /// The first `maxArguments` arguments with secret-looking values redacted (see
    /// `ArgumentRedaction`; `argv[0]` is kept), each capped at `maxArgumentLength` characters.
    static func cappedArguments(_ arguments: [String]) -> [String] {
        ArgumentRedaction.redact(Array(arguments.prefix(maxArguments))).map { String($0.prefix(maxArgumentLength)) }
    }

    static func dyldEnvironment(_ environment: [String: Any]) -> [String: String] {
        var result: [String: String] = [:]
        for (key, value) in environment where key.hasPrefix("DYLD_") {
            if let text = value as? String { result[key] = text }
        }
        return result
    }

    static func triggers(in plist: [String: Any]) -> [String] {
        triggerKeys.compactMap { key, trigger in plist[key] == nil ? nil : trigger }.sorted()
    }

    static func sessionType(_ value: Any?) -> String? {
        if let text = value as? String { return text }
        return (value as? [Any])?.first as? String
    }

    /// Parse all plists in a directory. Missing directories are silently skipped.
    /// With `skippingSymbolicLinks`, plists that are symbolic links are ignored (used for
    /// directories inside app bundles, where a link could point anywhere on the host).
    /// Returns (entries, errorMessages) - never throws.
    public func parseDirectory(
        at dirPath: String,
        skippingSymbolicLinks: Bool = false
    ) -> (entries: [ParsedEntry], errors: [String]) {
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

        for fullPath in paths where !(skippingSymbolicLinks && SymbolicLinks.isLink(atPath: fullPath)) {
            if let entry = parse(at: fullPath) {
                entries.append(entry)
            } else {
                errors.append("Skipped unparseable plist: \(fullPath)")
            }
        }

        return (entries, errors)
    }
}
