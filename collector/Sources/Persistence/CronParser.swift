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

    private struct ParsedCronLine {
        let user: String?
        let labelUser: String
        let command: String
        let runAtLoad: Bool
    }

    /// Parse /etc/crontab (system crontab, which includes a username field).
    func parseSystemCrontab(at path: String = "/etc/crontab") -> [CronEntry] {
        var errors: [String] = []
        return parseSystemCrontab(at: path, errors: &errors)
    }

    /// Parse /etc/crontab and report existing unreadable files.
    func parseSystemCrontab(at path: String = "/etc/crontab", errors: inout [String]) -> [CronEntry] {
        let fm = FileManager.default
        guard fm.fileExists(atPath: path) else { return [] }
        guard let text = try? String(contentsOfFile: path, encoding: .utf8) else {
            errors.append("Cannot read system crontab: \(path)")
            return []
        }
        return parseLines(text, filePath: path, hasUserField: true, defaultUser: "root")
    }

    /// Parse a user crontab from /var/at/tabs/<username>.
    func parseUserCrontab(at path: String, username: String) -> [CronEntry] {
        var errors: [String] = []
        return parseUserCrontab(at: path, username: username, errors: &errors)
    }

    /// Parse a user crontab and report existing unreadable files.
    func parseUserCrontab(at path: String, username: String, errors: inout [String]) -> [CronEntry] {
        let fm = FileManager.default
        guard fm.fileExists(atPath: path) else { return [] }
        guard let text = try? String(contentsOfFile: path, encoding: .utf8) else {
            errors.append("Cannot read user crontab: \(path)")
            return []
        }
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
            let result = parseUserCrontab(at: fullPath, username: filename, errors: &errors)
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
            guard let parsed = parseLine(rawLine, hasUserField: hasUserField, defaultUser: defaultUser) else {
                continue
            }

            index += 1
            results.append(CronEntry(
                label: "cron.\(parsed.labelUser).\(index)",
                path: filePath,
                program: parsed.command,
                runAtLoad: parsed.runAtLoad,
                user: parsed.user
            ))
        }

        return results
    }

    private func parseLine(
        _ rawLine: String,
        hasUserField: Bool,
        defaultUser: String?
    ) -> ParsedCronLine? {
        let line = rawLine.trimmingCharacters(in: .whitespaces)
        guard !line.isEmpty, !line.hasPrefix("#") else { return nil }

        if line.hasPrefix("@reboot") {
            return parseRebootLine(line, hasUserField: hasUserField, defaultUser: defaultUser)
        }
        return parseScheduledLine(line, hasUserField: hasUserField, defaultUser: defaultUser)
    }

    private func parseRebootLine(
        _ line: String,
        hasUserField: Bool,
        defaultUser: String?
    ) -> ParsedCronLine? {
        let rest = String(line.dropFirst("@reboot".count)).trimmingCharacters(in: .whitespaces)
        let (user, command) = splitUserAndCommand(rest, hasUserField: hasUserField, defaultUser: defaultUser)
        guard !command.isEmpty else { return nil }
        return ParsedCronLine(
            user: user,
            labelUser: defaultUser ?? "unknown",
            command: command,
            runAtLoad: true
        )
    }

    private func parseScheduledLine(
        _ line: String,
        hasUserField: Bool,
        defaultUser: String?
    ) -> ParsedCronLine? {
        let parts = line.split(separator: " ", maxSplits: hasUserField ? 6 : 5, omittingEmptySubsequences: true)
        let minFields = hasUserField ? 7 : 6
        guard parts.count >= minFields else { return nil }

        let user = hasUserField ? String(parts[5]) : defaultUser
        let commandStart = hasUserField ? 6 : 5
        let command = parts.dropFirst(commandStart)
            .joined(separator: " ")
            .trimmingCharacters(in: .whitespaces)
        guard !command.isEmpty else { return nil }

        return ParsedCronLine(
            user: user,
            labelUser: user ?? "unknown",
            command: command,
            runAtLoad: false
        )
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
