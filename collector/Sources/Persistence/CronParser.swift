import Foundation
import HostCommand

/// Parses crontab files into LaunchItem records.
///
/// Handles:
///   - System crontab: /etc/crontab  (has username field after schedule)
///   - User crontabs:  /var/at/tabs/<username>  (no username field, runs as file owner)
///   - @reboot shortcut (runAtLoad = true)
///   - @hourly/@daily/@weekly/@monthly/@yearly/@annually (and @midnight) shortcuts
struct CronParser {

    private static let scheduleMacros: Set<String> = [
        "@hourly", "@daily", "@midnight", "@weekly", "@monthly", "@yearly", "@annually",
    ]

    struct CronEntry {
        let label: String
        let path: String
        let program: String?
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
        guard let text = readCrontab(at: path, errors: &errors, kind: "system") else { return [] }
        return parseLines(text, filePath: path, hasUserField: true, defaultUser: "root")
    }

    /// Parse a user crontab from /var/at/tabs/<username>.
    func parseUserCrontab(at path: String, username: String) -> [CronEntry] {
        var errors: [String] = []
        return parseUserCrontab(at: path, username: username, errors: &errors)
    }

    /// Parse a user crontab and report existing unreadable files.
    func parseUserCrontab(at path: String, username: String, errors: inout [String]) -> [CronEntry] {
        guard let text = readCrontab(at: path, errors: &errors, kind: "user") else { return [] }
        return parseLines(text, filePath: path, hasUserField: false, defaultUser: username)
    }

    private func readCrontab(at path: String, errors: inout [String], kind: String) -> String? {
        let fm = FileManager.default
        guard fm.fileExists(atPath: path) else { return nil }
        guard let data = try? BoundedFileReader.read(path: path),
              let text = String(data: data, encoding: .utf8) else {
            errors.append("Cannot read \(kind) crontab: \(path)")
            return nil
        }
        return text
    }

    /// Enumerate and parse all accessible user crontabs under /var/at/tabs/.
    func parseAllUserCrontabs() -> ([CronEntry], [String]) {
        let tabsDir = "/var/at/tabs"
        let fm = FileManager.default

        guard fm.fileExists(atPath: tabsDir) else { return ([], []) }
        guard let files = (try? fm.contentsOfDirectory(atPath: tabsDir))?.sorted() else {
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
                program: Self.firstToken(of: parsed.command),
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

        if line.hasPrefix("@") {
            return parseMacroLine(line, hasUserField: hasUserField, defaultUser: defaultUser)
        }
        return parseScheduledLine(line, hasUserField: hasUserField, defaultUser: defaultUser)
    }

    private func parseMacroLine(
        _ line: String,
        hasUserField: Bool,
        defaultUser: String?
    ) -> ParsedCronLine? {
        guard let macro = line.split(whereSeparator: Self.isWhitespace).first.map(String.init) else {
            return nil
        }
        let isReboot = macro == "@reboot"
        guard isReboot || Self.scheduleMacros.contains(macro) else { return nil }
        let rest = String(line.dropFirst(macro.count)).trimmingCharacters(in: .whitespaces)
        let (user, command) = splitUserAndCommand(rest, hasUserField: hasUserField, defaultUser: defaultUser)
        guard !command.isEmpty else { return nil }
        return ParsedCronLine(
            user: user,
            labelUser: defaultUser ?? "unknown",
            command: command,
            runAtLoad: isReboot
        )
    }

    private func parseScheduledLine(
        _ line: String,
        hasUserField: Bool,
        defaultUser: String?
    ) -> ParsedCronLine? {
        let parts = line.split(
            maxSplits: hasUserField ? 6 : 5,
            omittingEmptySubsequences: true,
            whereSeparator: Self.isWhitespace
        )
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
        let parts = rest.split(maxSplits: 1, omittingEmptySubsequences: true, whereSeparator: Self.isWhitespace)
        guard parts.count == 2 else { return (defaultUser, rest) }
        return (String(parts[0]), String(parts[1]).trimmingCharacters(in: .whitespaces))
    }

    private static func isWhitespace(_ character: Character) -> Bool {
        character == " " || character == "\t"
    }

    private static func firstToken(of command: String) -> String? {
        command.split(whereSeparator: isWhitespace).first.map(String.init)
    }
}
