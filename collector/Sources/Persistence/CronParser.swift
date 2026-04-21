import Foundation

/// Parses crontab files into LaunchItem records.
///
/// Handles:
///   - System crontab: /etc/crontab  (has username field after schedule)
///   - User crontabs:  /var/at/tabs/<username>  (no username field, runs as file owner)
///   - @reboot shortcut (runAtLoad = true)
struct CronParser {

    struct CronEntry {
        let label: String
        let path: String
        let program: String
        let runAtLoad: Bool
        let user: String?
    }

    /// Parse /etc/crontab (system crontab, which includes a username field).
    func parseSystemCrontab(at path: String = "/etc/crontab") -> [CronEntry] {
        guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { return [] }
        return parseLines(text, filePath: path, hasUserField: true, defaultUser: "root")
    }

    /// Parse a user crontab from /var/at/tabs/<username>.
    func parseUserCrontab(at path: String, username: String) -> [CronEntry] {
        guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { return [] }
        return parseLines(text, filePath: path, hasUserField: false, defaultUser: username)
    }

    /// Enumerate and parse all accessible user crontabs under /var/at/tabs/.
    func parseAllUserCrontabs() -> ([CronEntry], [String]) {
        let tabsDir = "/var/at/tabs"
        let fm = FileManager.default

        guard fm.fileExists(atPath: tabsDir) else { return ([], []) }
        guard let files = try? fm.contentsOfDirectory(atPath: tabsDir) else {
            return ([], ["Cannot read /var/at/tabs (requires root)"])
        }

        var entries: [CronEntry] = []
        var errors: [String] = []

        for filename in files {
            let fullPath = (tabsDir as NSString).appendingPathComponent(filename)
            let result = parseUserCrontab(at: fullPath, username: filename)
            if result.isEmpty {
                errors.append("Skipped unreadable crontab: \(fullPath)")
            }
            entries.append(contentsOf: result)
        }

        return (entries, errors)
    }

    // MARK: - Private

    private func parseLines(
        _ text: String,
        filePath: String,
        hasUserField: Bool,
        defaultUser: String?
    ) -> [CronEntry] {
        var results: [CronEntry] = []
        var index = 0

        for rawLine in text.components(separatedBy: "\n") {
            let line = rawLine.trimmingCharacters(in: .whitespaces)

            // Skip blank lines and comments
            guard !line.isEmpty, !line.hasPrefix("#") else { continue }

            // @reboot shortcut
            if line.hasPrefix("@reboot") {
                let rest = String(line.dropFirst("@reboot".count)).trimmingCharacters(in: .whitespaces)
                let (user, command) = splitUserAndCommand(rest, hasUserField: hasUserField, defaultUser: defaultUser)
                if !command.isEmpty {
                    index += 1
                    results.append(CronEntry(
                        label: "cron.\(defaultUser ?? "unknown").\(index)",
                        path: filePath,
                        program: command,
                        runAtLoad: true,
                        user: user
                    ))
                }
                continue
            }

            // Standard 5-field schedule: min hour dom month dow [user] command
            let parts = line.split(separator: " ", maxSplits: hasUserField ? 6 : 5, omittingEmptySubsequences: true)
            let minFields = hasUserField ? 7 : 6
            guard parts.count >= minFields else { continue }

            let commandPart: String
            let user: String?
            if hasUserField {
                user = String(parts[5])
                commandPart = parts.dropFirst(6).joined(separator: " ")
            } else {
                user = defaultUser
                commandPart = parts.dropFirst(5).joined(separator: " ")
            }

            // Extract the binary (first token of the command)
            let command = commandPart.trimmingCharacters(in: .whitespaces)
            guard !command.isEmpty else { continue }

            index += 1
            results.append(CronEntry(
                label: "cron.\(user ?? "unknown").\(index)",
                path: filePath,
                program: command,
                runAtLoad: false,
                user: user
            ))
        }

        return results
    }

    private func splitUserAndCommand(
        _ rest: String,
        hasUserField: Bool,
        defaultUser: String?
    ) -> (user: String?, command: String) {
        guard hasUserField else { return (defaultUser, rest) }
        let parts = rest.split(separator: " ", maxSplits: 1, omittingEmptySubsequences: true)
        guard parts.count == 2 else { return (defaultUser, rest) }
        return (String(parts[0]), String(parts[1]))
    }
}
