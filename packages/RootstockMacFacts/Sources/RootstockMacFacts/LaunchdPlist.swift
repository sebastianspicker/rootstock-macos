import Foundation

/// Lightweight launchd plist discovery and field extraction (product-neutral).
public enum LaunchdPlistFacts: Sendable {
    public struct Summary: Sendable, Equatable {
        public var path: String
        public var label: String?
        public var program: String?
        public var programArguments: [String]
        public var userName: String?
        public var runAtLoad: Bool
        public var keepAlive: Bool

        public init(
            path: String,
            label: String? = nil,
            program: String? = nil,
            programArguments: [String] = [],
            userName: String? = nil,
            runAtLoad: Bool = false,
            keepAlive: Bool = false
        ) {
            self.path = path
            self.label = label
            self.program = program
            self.programArguments = programArguments
            self.userName = userName
            self.runAtLoad = runAtLoad
            self.keepAlive = keepAlive
        }

        /// Arguments with Program prepended when ProgramArguments was empty.
        public var effectiveArguments: [String] {
            if !programArguments.isEmpty { return programArguments }
            if let program { return [program] }
            return []
        }
    }

    /// Standard live-host launchd directories (product inventory paths).
    public static var standardDirectories: [String] {
        [
            MacSecurityPaths.appleLaunchDaemons,
            MacSecurityPaths.systemLaunchDaemons,
            MacSecurityPaths.systemLaunchAgents,
            MacSecurityPaths.userLaunchAgents(
                home: FileManager.default.homeDirectoryForCurrentUser
            ).path,
        ]
    }

    /// Enumerate `*.plist` files directly under `directory` (non-recursive).
    public static func listPlistPaths(
        in directory: String,
        fileManager: FileManager = .default
    ) -> [String] {
        guard fileManager.fileExists(atPath: directory) else {
            return []
        }
        guard let names = try? fileManager.contentsOfDirectory(atPath: directory) else {
            return []
        }
        return names
            .filter { $0.hasSuffix(".plist") }
            .map { (directory as NSString).appendingPathComponent($0) }
            .sorted()
    }

    /// Read Label / Program / ProgramArguments / RunAtLoad / KeepAlive when parseable.
    public static func summarize(plistPath: String) -> Summary {
        var summary = Summary(path: plistPath)
        guard let dict = loadDict(at: plistPath) else {
            return summary
        }
        apply(dict: dict, to: &summary)
        return summary
    }

    /// Summarize from an already-loaded property list dictionary (offline trees).
    public static func summarize(path: String, dict: [String: Any]) -> Summary {
        var summary = Summary(path: path)
        apply(dict: dict, to: &summary)
        return summary
    }

    /// Parse all plists under a directory. Missing directory → empty list (no error).
    public static func summarizeDirectory(
        at directory: String,
        fileManager: FileManager = .default
    ) -> [Summary] {
        listPlistPaths(in: directory, fileManager: fileManager).map { summarize(plistPath: $0) }
    }

    /// Extract program path from Program or first ProgramArguments element.
    public static func program(from dict: [String: Any]) -> String? {
        if let prog = dict["Program"] as? String, !prog.isEmpty {
            return prog
        }
        if let args = dict["ProgramArguments"] as? [String], let first = args.first, !first.isEmpty {
            return first
        }
        return nil
    }

    public static func programArguments(from dict: [String: Any]) -> [String] {
        if let args = dict["ProgramArguments"] as? [String] {
            return args
        }
        return []
    }

    public static func resolveKeepAlive(_ value: Any?) -> Bool {
        if let b = value as? Bool { return b }
        if let dict = value as? [String: Any] {
            // KeepAlive can be a dict of conditions; treat non-empty as true-ish intent.
            return !dict.isEmpty
        }
        return false
    }

    // MARK: - Private

    private static func loadDict(at path: String) -> [String: Any]? {
        if let dict = NSDictionary(contentsOfFile: path) as? [String: Any] {
            return dict
        }
        guard let data = FileManager.default.contents(atPath: path) else { return nil }
        var format = PropertyListSerialization.PropertyListFormat.xml
        return try? PropertyListSerialization.propertyList(
            from: data, options: [], format: &format
        ) as? [String: Any]
    }

    private static func apply(dict: [String: Any], to summary: inout Summary) {
        if let label = dict["Label"] as? String {
            summary.label = label
        }
        summary.program = program(from: dict)
        summary.programArguments = programArguments(from: dict)
        if summary.program == nil {
            summary.program = summary.programArguments.first
        }
        summary.userName = dict["UserName"] as? String
        summary.runAtLoad = dict["RunAtLoad"] as? Bool ?? false
        summary.keepAlive = resolveKeepAlive(dict["KeepAlive"])
    }
}
