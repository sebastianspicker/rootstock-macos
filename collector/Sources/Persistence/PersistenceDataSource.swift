import Foundation
import Models
import HostCommand
import RootstockMacFacts
import LaunchdPlists

/// Enumerates all persistence mechanisms on the system.
///
/// Sources scanned:
///   • LaunchDaemons: /System/Library/LaunchDaemons/, /Library/LaunchDaemons/
///   • LaunchAgents:  /Library/LaunchAgents/, ~/Library/LaunchAgents/
///   • App-embedded:  <App>.app/Contents/Library/{LaunchAgents,LaunchDaemons,LoginItems}
///   • Login Items:   ~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm
///   • Login hooks:   LoginHook / LogoutHook in com.apple.loginwindow preferences
///   • Cron jobs:     /etc/crontab, /var/at/tabs/<user>
///
/// Launchd directory inventory uses `LaunchdPlistParser` backed by
/// `LaunchdPlistFacts` (RootstockMacFacts). Loaded state comes from one
/// `launchctl list` and one `launchctl print system` run.
public struct PersistenceDataSource: DataSource {
    public let name = "Persistence"
    public let requiresElevation = false

    private let cronParser = CronParser()
    let plistParser = LaunchdPlistParser()
    private let signingIdentity = ProgramSigningIdentity()

    /// Applications from the scan whose bundles may embed launchd jobs or login items.
    let knownApps: [Application]

    private static let daemonDirs = [
        MacSecurityPaths.appleLaunchDaemons,
        MacSecurityPaths.systemLaunchDaemons,
    ]

    private static let agentDirs = [
        MacSecurityPaths.systemLaunchAgents,
        MacSecurityPaths.userLaunchAgents(
            home: FileManager.default.homeDirectoryForCurrentUser
        ).path,
    ]

    public init(knownApps: [Application] = []) {
        self.knownApps = knownApps
    }

    public func collect() async -> DataSourceResult {
        var items: [LaunchItem] = []
        var errors: [CollectionError] = []

        let (loadedState, launchctlErrors) = LaunchctlLoadedState.collect()
        appendRecoverableErrors(launchctlErrors, to: &errors)

        // 1. LaunchDaemons
        for dir in Self.daemonDirs {
            let (entries, errs) = parseLaunchdDirectory(at: dir)
            items += entries.map { launchItemFrom($0, type: .daemon, loadedState: loadedState) }
            appendRecoverableErrors(errs, to: &errors)
        }

        // 2. LaunchAgents
        for dir in Self.agentDirs {
            let (entries, errs) = parseLaunchdDirectory(at: dir)
            items += entries.map { launchItemFrom($0, type: .agent, loadedState: loadedState) }
            appendRecoverableErrors(errs, to: &errors)
        }

        // 3. Launchd jobs and login items embedded in application bundles
        let (embeddedItems, embeddedErrors) = collectEmbeddedItems(loadedState: loadedState)
        items += embeddedItems
        appendRecoverableErrors(embeddedErrors, to: &errors)

        // 4. Login Items (BTM database)
        let (loginItems, loginErrors) = collectLoginItems()
        items += loginItems.map { withProgramFacts($0, plistModified: nil) }
        appendRecoverableErrors(loginErrors, to: &errors)

        // 5. Login hooks
        items += collectLoginHooks()

        // 6. Cron jobs
        let (cronItems, cronErrors) = collectCronJobs()
        items += cronItems.map { withProgramFacts($0, plistModified: FileTimestamp.modified(path: $0.path)) }
        appendRecoverableErrors(cronErrors, to: &errors)

        return DataSourceResult(nodes: items, errors: errors)
    }

    private func appendRecoverableErrors(
        _ messages: [String],
        to errors: inout [CollectionError]
    ) {
        errors += messages.map {
            CollectionError(source: name, message: $0, recoverable: true)
        }
    }

    // MARK: - Launchd plist parsing (delegates to shared LaunchdPlistParser)

    private func parseLaunchdDirectory(at dirPath: String) -> ([LaunchdPlistParser.ParsedEntry], [String]) {
        plistParser.parseDirectory(at: dirPath)
    }

    func launchItemFrom(
        _ entry: LaunchdPlistParser.ParsedEntry,
        type: LaunchItem.ItemType,
        loadedState: LaunchctlLoadedState,
        bundlePath: String? = nil
    ) -> LaunchItem {
        let facts = ProgramFacts(program: entry.program)
        return LaunchItem(
            label: entry.label,
            path: entry.plistPath,
            type: type,
            program: entry.program,
            runAtLoad: entry.runAtLoad,
            user: entry.user,
            ownership: ownership(plistPath: entry.plistPath, program: entry.program),
            details: LaunchItem.Details(
                programArguments: entry.programArguments,
                environmentVariableNames: entry.environmentVariableNames,
                dyldEnvironment: entry.dyldEnvironment,
                triggers: entry.triggers,
                intervalSeconds: entry.intervalSeconds,
                sessionType: entry.sessionType,
                disabled: entry.disabled,
                loaded: loadedState.loaded(label: entry.label, type: type),
                programExists: facts.exists,
                programSha256: facts.sha256,
                plistModified: entry.plistModified,
                bundlePath: bundlePath
            )
        )
    }

    /// Ownership and signing identity of a configuration file and the program it starts.
    func ownership(plistPath: String, program: String?) -> LaunchItem.Ownership {
        let plistOwnership = fileOwnership(at: plistPath)
        let programOwnership = program.map { fileOwnership(at: $0) }
        // Apple's own launchd jobs under /System carry no team identifier and never
        // belong to a third-party app, so only other plists are worth a signature read.
        let identity: ProgramSigningIdentity.Identity? = plistPath.hasPrefix("/System/")
            ? nil
            : program.flatMap { signingIdentity.identity(forProgramAt: $0) }
        return LaunchItem.Ownership(
            plistOwner: plistOwnership.owner,
            programOwner: programOwnership?.owner,
            plistWritableByNonRoot: plistOwnership.writableByNonRoot,
            programWritableByNonRoot: programOwnership?.writableByNonRoot ?? false,
            programTeamId: identity?.teamId,
            programSigningId: identity?.signingId
        )
    }

    /// Existence and digest of a launch item's program.
    struct ProgramFacts {
        let exists: Bool?
        let sha256: String?

        /// Relative programs (e.g. bare names resolved through launchd's PATH) are not probed:
        /// they would resolve against the collector's working directory instead.
        init(program: String?) {
            guard let program, program.hasPrefix("/") else {
                exists = nil
                sha256 = nil
                return
            }
            exists = FileManager.default.fileExists(atPath: program)
            sha256 = program.hasPrefix("/System/") ? nil : FileDigest.sha256(ofFileAt: program)
        }
    }

    /// Copy of `item` with program existence, digest and source modification time filled in.
    private func withProgramFacts(_ item: LaunchItem, plistModified: String?) -> LaunchItem {
        let facts = ProgramFacts(program: item.program)
        return LaunchItem(
            label: item.label,
            path: item.path,
            type: item.type,
            program: item.program,
            runAtLoad: item.runAtLoad,
            user: item.user,
            ownership: LaunchItem.Ownership(
                plistOwner: item.plistOwner,
                programOwner: item.programOwner,
                plistWritableByNonRoot: item.plistWritableByNonRoot,
                programWritableByNonRoot: item.programWritableByNonRoot,
                programTeamId: item.programTeamId,
                programSigningId: item.programSigningId
            ),
            details: LaunchItem.Details(
                programArguments: item.programArguments,
                programExists: facts.exists,
                programSha256: facts.sha256,
                plistModified: plistModified
            )
        )
    }

    // MARK: - File ownership

    private struct FileOwnership {
        let owner: String?
        let writableByNonRoot: Bool
    }

    private static let rootEquivalentGroups: Set<String> = ["wheel", "daemon"]

    private func fileOwnership(at path: String) -> FileOwnership {
        let fm = FileManager.default
        guard let attrs = try? fm.attributesOfItem(atPath: path) else {
            return FileOwnership(owner: nil, writableByNonRoot: false)
        }
        let owner = attrs[.ownerAccountName] as? String
        let group = attrs[.groupOwnerAccountName] as? String
        let posix = (attrs[.posixPermissions] as? Int) ?? 0
        // Other-writable (0o002) is always non-root writable.
        // Group-writable (0o020) only counts if the group is not root-equivalent.
        let otherWritable = (posix & 0o002) != 0
        let groupWritable = (posix & 0o020) != 0
            && !Self.rootEquivalentGroups.contains(group ?? "wheel")
        return FileOwnership(owner: owner, writableByNonRoot: otherWritable || groupWritable)
    }

    // MARK: - Login Items (BTM)

    /// The BackgroundItems store grows with every registered item; a few MiB is normal.
    static let maximumBTMBytes = 16 * 1024 * 1024

    private func collectLoginItems() -> ([LaunchItem], [String]) {
        let btmPath = NSHomeDirectory() + "/" + MacSecurityPaths.backgroundItemsBTMRelative

        let fm = FileManager.default
        guard fm.fileExists(atPath: btmPath) else {
            // No BTM file - try sfltool fallback (Sequoia+)
            return collectLoginItemsViaSfltool()
        }
        guard let data = try? BoundedFileReader.read(path: btmPath, limit: Self.maximumBTMBytes) else {
            return collectLoginItemsViaSfltool()
        }

        // BTM is a binary plist on older macOS; attempt plist deserialization
        guard let plist = Shell.parsePlistDict(from: data) else {
            // BTM format on newer macOS is a custom binary - fall back to sfltool
            let (sfltoolItems, sfltoolErrors) = collectLoginItemsViaSfltool()
            if sfltoolItems.isEmpty {
                return ([], ["BTM file format not parseable as plist (newer macOS): \(btmPath)"] + sfltoolErrors)
            }
            return (sfltoolItems, sfltoolErrors)
        }

        // Extract login items from whatever structure we find
        var items: [LaunchItem] = []
        extractLoginItemsFromPlist(plist, path: btmPath, into: &items)
        return (items, [])
    }

    private func collectLoginItemsViaSfltool() -> ([LaunchItem], [String]) {
        let outcome = Shell.execute(
            "/usr/bin/sfltool",
            ["dumpbtm"],
            timeoutSeconds: 5
        )
        guard case .success(let result) = outcome else {
            return (
                [],
                ["sfltool dumpbtm failed: \(outcome.failureDescription ?? "command failure")"]
            )
        }
        return (Self.parseSfltoolOutput(result.stdout), [])
    }

    /// Parse `sfltool dumpbtm` output to extract login items.
    /// Format is semi-structured text with entries like:
    ///   Type: login item
    ///   Name: AppName
    ///   Identifier: com.example.app
    ///   URL: file:///Applications/App.app
    ///   Developer: TeamID
    internal static func parseSfltoolOutput(_ output: String) -> [LaunchItem] {
        var items: [LaunchItem] = []
        var record = SfltoolRecord()

        for line in output.split(separator: "\n", omittingEmptySubsequences: false) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)

            if isSfltoolRecordSeparator(trimmed) {
                appendSfltoolItem(from: record, into: &items)
                record.reset()
                continue
            }

            record.apply(trimmed)
        }

        appendSfltoolItem(from: record, into: &items)
        return items
    }

    private static func isSfltoolRecordSeparator(_ line: String) -> Bool {
        line.isEmpty || line.hasPrefix("===") || line.hasPrefix("---")
    }

    private static func appendSfltoolItem(
        from record: SfltoolRecord,
        into items: inout [LaunchItem]
    ) {
        guard let item = record.launchItem() else { return }
        items.append(item)
    }

    private struct SfltoolRecord {
        var identifier: String?
        var url: String?
        var type: String?

        mutating func reset() {
            identifier = nil
            url = nil
            type = nil
        }

        mutating func apply(_ line: String) {
            if let value = Self.value(in: line, after: "Identifier:") {
                identifier = value
            } else if let value = Self.value(in: line, after: "URL:") {
                url = value
            } else if let value = Self.value(in: line, after: "Type:") {
                type = value.lowercased()
            }
        }

        func launchItem() -> LaunchItem? {
            guard let identifier, let path = resolvedPath() else { return nil }
            return LaunchItem(
                label: identifier,
                path: path,
                type: type == "login item" ? .loginItem : .agent,
                program: path,
                runAtLoad: true,
                user: nil
            )
        }

        private func resolvedPath() -> String? {
            guard let url else { return nil }
            guard url.hasPrefix("file://") else { return url }
            return URL(string: url)?.path
        }

        private static func value(in line: String, after marker: String) -> String? {
            guard let range = line.range(of: marker) else { return nil }
            return String(line[range.upperBound...]).trimmingCharacters(in: .whitespaces)
        }
    }

    private func extractLoginItemsFromPlist(
        _ plist: [String: Any],
        path: String,
        into items: inout [LaunchItem]
    ) {
        // Common keys found in BTM / legacy login item plists
        for key in ["Items", "LoginItems", "SMLoginItems"] {
            if let array = plist[key] as? [[String: Any]] {
                for (i, item) in array.enumerated() {
                    let label = (item["BundleIdentifier"] as? String)
                        ?? (item["Name"] as? String)
                        ?? "login_item.\(i)"
                    let program = item["Path"] as? String
                        ?? item["ExecutablePath"] as? String
                    items.append(LaunchItem(
                        label: label,
                        path: path,
                        type: .loginItem,
                        program: program,
                        runAtLoad: true,
                        user: nil
                    ))
                }
            }
        }
    }

    // MARK: - Cron jobs

    private func collectCronJobs() -> ([LaunchItem], [String]) {
        var items: [LaunchItem] = []
        var errors: [String] = []

        // System crontab
        let systemEntries = cronParser.parseSystemCrontab(errors: &errors)
        items += systemEntries.map {
            LaunchItem(
                label: $0.label,
                path: $0.path,
                type: .cron,
                program: $0.program,
                runAtLoad: $0.runAtLoad,
                user: $0.user
            )
        }

        // Per-user crontabs (requires read access to /var/at/tabs)
        let (userEntries, userErrors) = cronParser.parseAllUserCrontabs()
        items += userEntries.map {
            LaunchItem(
                label: $0.label,
                path: $0.path,
                type: .cron,
                program: $0.program,
                runAtLoad: $0.runAtLoad,
                user: $0.user
            )
        }
        errors += userErrors

        return (items, errors)
    }

}
