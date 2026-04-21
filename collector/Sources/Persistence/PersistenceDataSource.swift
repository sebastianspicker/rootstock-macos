import Foundation
import Models
import XPCServices

/// Enumerates all persistence mechanisms on the system.
///
/// Sources scanned:
///   • LaunchDaemons: /System/Library/LaunchDaemons/, /Library/LaunchDaemons/
///   • LaunchAgents:  /Library/LaunchAgents/, ~/Library/LaunchAgents/
///   • Login Items:   ~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm
///   • Cron jobs:     /etc/crontab, /var/at/tabs/<user>
///   • Login hooks:   /var/root/Library/Preferences/com.apple.loginwindow.plist
public struct PersistenceDataSource: DataSource {
    public let name = "Persistence"
    public let requiresElevation = false

    private let cronParser = CronParser()
    private let plistParser = LaunchdPlistParser()

    private static let daemonDirs = [
        "/System/Library/LaunchDaemons",
        "/Library/LaunchDaemons",
    ]

    private static let agentDirs = [
        "/Library/LaunchAgents",
        NSHomeDirectory() + "/Library/LaunchAgents",
    ]

    public init() { }

    public func collect() async -> DataSourceResult {
        var items: [LaunchItem] = []
        var errors: [CollectionError] = []

        // 1. LaunchDaemons
        for dir in Self.daemonDirs {
            let (entries, errs) = parseLaunchdDirectory(at: dir)
            items += entries.map { launchItemFrom($0, type: .daemon) }
            errors += errs.map { CollectionError(source: name, message: $0, recoverable: true) }
        }

        // 2. LaunchAgents
        for dir in Self.agentDirs {
            let (entries, errs) = parseLaunchdDirectory(at: dir)
            items += entries.map { launchItemFrom($0, type: .agent) }
            errors += errs.map { CollectionError(source: name, message: $0, recoverable: true) }
        }

        // 3. Login Items (BTM database)
        let (loginItems, loginErrors) = collectLoginItems()
        items += loginItems
        errors += loginErrors.map { CollectionError(source: name, message: $0, recoverable: true) }

        // 4. Cron jobs
        let (cronItems, cronErrors) = collectCronJobs()
        items += cronItems
        errors += cronErrors.map { CollectionError(source: name, message: $0, recoverable: true) }

        // 5. Login hooks (legacy)
        let (hookItems, hookErrors) = collectLoginHooks()
        items += hookItems
        errors += hookErrors.map { CollectionError(source: name, message: $0, recoverable: true) }

        return DataSourceResult(nodes: items, errors: errors)
    }

    // MARK: - Launchd plist parsing (delegates to shared LaunchdPlistParser)

    private func parseLaunchdDirectory(at dirPath: String) -> ([LaunchdPlistParser.ParsedEntry], [String]) {
        plistParser.parseDirectory(at: dirPath)
    }

    private func launchItemFrom(_ entry: LaunchdPlistParser.ParsedEntry, type: LaunchItem.ItemType) -> LaunchItem {
        let plistOwnership = fileOwnership(at: entry.plistPath)
        let programOwnership = entry.program.map { fileOwnership(at: $0) }

        return LaunchItem(
            label: entry.label,
            path: entry.plistPath,
            type: type,
            program: entry.program,
            runAtLoad: entry.runAtLoad,
            user: entry.user,
            plistOwner: plistOwnership.owner,
            programOwner: programOwnership?.owner,
            plistWritableByNonRoot: plistOwnership.writableByNonRoot,
            programWritableByNonRoot: programOwnership?.writableByNonRoot ?? false
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

    private func collectLoginItems() -> ([LaunchItem], [String]) {
        let btmPath = NSHomeDirectory()
            + "/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm"

        let fm = FileManager.default
        guard fm.fileExists(atPath: btmPath) else {
            // No BTM file — try sfltool fallback (Sequoia+)
            return collectLoginItemsViaSfltool()
        }
        guard let data = fm.contents(atPath: btmPath) else {
            return collectLoginItemsViaSfltool()
        }

        // BTM is a binary plist on older macOS; attempt plist deserialization
        guard let plist = Shell.parsePlistDict(from: data) else {
            // BTM format on newer macOS is a custom binary — fall back to sfltool
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
        guard let output = Shell.run("/usr/bin/sfltool", ["dumpbtm"], timeoutSeconds: 5) else {
            return ([], [])
        }
        return (Self.parseSfltoolOutput(output), [])
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
        var currentIdentifier: String?
        var currentURL: String?
        var currentType: String?

        let flushItem = { () -> Void in
            guard let identifier = currentIdentifier else { return }
            let path = currentURL.flatMap { urlString -> String? in
                guard urlString.hasPrefix("file://") else { return urlString }
                return URL(string: urlString)?.path
            }
            guard let resolvedPath = path else { return }  // skip entries with no parseable path
            items.append(LaunchItem(
                label: identifier,
                path: resolvedPath,
                type: currentType == "login item" ? .loginItem : .agent,
                program: resolvedPath,
                runAtLoad: true,
                user: nil
            ))
        }

        for line in output.split(separator: "\n", omittingEmptySubsequences: false) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)

            if trimmed.isEmpty || trimmed.hasPrefix("===") || trimmed.hasPrefix("---") {
                flushItem()
                currentIdentifier = nil
                currentURL = nil
                currentType = nil
                continue
            }

            if let range = trimmed.range(of: "Identifier:") {
                currentIdentifier = String(trimmed[range.upperBound...]).trimmingCharacters(in: .whitespaces)
            } else if let range = trimmed.range(of: "URL:") {
                currentURL = String(trimmed[range.upperBound...]).trimmingCharacters(in: .whitespaces)
            } else if let range = trimmed.range(of: "Type:") {
                currentType = String(trimmed[range.upperBound...]).trimmingCharacters(in: .whitespaces).lowercased()
            }
        }

        flushItem()
        return items
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
        let systemEntries = cronParser.parseSystemCrontab()
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

    // MARK: - Login hooks (legacy)

    private func collectLoginHooks() -> ([LaunchItem], [String]) {
        let paths = [
            "/private/var/root/Library/Preferences/com.apple.loginwindow.plist",
            NSHomeDirectory() + "/Library/Preferences/com.apple.loginwindow.plist",
        ]

        var items: [LaunchItem] = []
        var errors: [String] = []

        for path in paths {
            guard FileManager.default.fileExists(atPath: path) else { continue }
            guard let data = FileManager.default.contents(atPath: path) else {
                errors.append("Cannot read loginwindow plist (requires root): \(path)")
                continue
            }

            var format = PropertyListSerialization.PropertyListFormat.xml
            guard let plist = try? PropertyListSerialization.propertyList(
                from: data, options: [], format: &format
            ) as? [String: Any] else {
                errors.append("Cannot parse loginwindow plist: \(path)")
                continue
            }

            for hookKey in ["LoginHook", "LogoutHook"] {
                if let script = plist[hookKey] as? String {
                    items.append(LaunchItem(
                        label: "loginwindow.\(hookKey)",
                        path: path,
                        type: .loginHook,
                        program: script,
                        runAtLoad: hookKey == "LoginHook",
                        user: path.contains("/root/") ? "root" : nil
                    ))
                }
            }
        }

        return (items, errors)
    }
}
