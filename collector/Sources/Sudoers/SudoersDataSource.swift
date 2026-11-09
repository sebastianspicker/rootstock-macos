import Foundation
import Models
import RootstockMacFacts

/// Parses /etc/sudoers and /etc/sudoers.d/* for NOPASSWD rules.
public struct SudoersDataSource: DataSource {
    public let name = "Sudoers"
    public let requiresElevation = false

    private let sudoersPath: String
    private let includeDirectoryPath: String

    public init() {
        self.init(sudoersPath: MacSecurityPaths.sudoers, includeDirectoryPath: MacSecurityPaths.sudoersD)
    }

    internal init(sudoersPath: String, includeDirectoryPath: String) {
        self.sudoersPath = sudoersPath
        self.includeDirectoryPath = includeDirectoryPath
    }

    public func collect() async -> DataSourceResult {
        var rules: [SudoersRule] = []
        var errors: [CollectionError] = []

        // Main sudoers file
        let (mainRules, mainErrors) = parseSudoersFile(at: sudoersPath)
        rules += mainRules
        errors += mainErrors.map { CollectionError(source: name, message: $0, recoverable: true) }

        // Included files from sudoers.d
        let fm = FileManager.default
        if fm.fileExists(atPath: includeDirectoryPath) {
            do {
                // sudo skips include-directory entries containing '.' or ending in '~'
                // and reads the rest in lexical order.
                let files = try fm.contentsOfDirectory(atPath: includeDirectoryPath).sorted()
                for file in files where !file.contains(".") && !file.hasSuffix("~") {
                    let path = (includeDirectoryPath as NSString).appendingPathComponent(file)
                    let (subRules, subErrors) = parseSudoersFile(at: path)
                    rules += subRules
                    errors += subErrors.map { CollectionError(source: name, message: $0, recoverable: true) }
                }
            } catch {
                errors.append(CollectionError(
                    source: name,
                    message: "Cannot list sudoers include directory: \(includeDirectoryPath)",
                    recoverable: true
                ))
            }
        }

        return DataSourceResult(nodes: rules, errors: errors)
    }

    private func parseSudoersFile(at path: String) -> ([SudoersRule], [String]) {
        do {
            // Lossy decode: one stray non-UTF-8 byte (e.g. a Latin-1 comment) must not drop every rule.
            let content = String(decoding: try Data(contentsOf: URL(fileURLWithPath: path)), as: UTF8.self)
            return (Self.parseSudoersContent(content), [])
        } catch let error as NSError where error.domain == NSCocoaErrorDomain && error.code == NSFileReadNoSuchFileError {
            return ([], ["Cannot read sudoers file: \(path)"])
        } catch let error as NSError where error.domain == NSCocoaErrorDomain && error.code == NSFileReadNoPermissionError {
            return ([], ["Cannot read sudoers file (requires elevation): \(path)"])
        } catch {
            return ([], ["Cannot read sudoers file: \(path) (\(error.localizedDescription))"])
        }
    }

    /// Parse sudoers file content for user rules.
    /// Format: `user  host = (runas) [NOPASSWD:] command`
    internal static func parseSudoersContent(_ content: String) -> [SudoersRule] {
        var rules: [SudoersRule] = []

        for trimmed in logicalLines(content) {
            // Skip comments (including #include/#includedir directives),
            // Defaults, aliases, and @include directives.
            // Note: #include to non-standard paths is not followed;
            // /etc/sudoers.d/ is enumerated separately by the caller.
            guard !trimmed.isEmpty,
                  !isComment(trimmed),
                  !trimmed.hasPrefix("Defaults"),
                  !trimmed.hasPrefix("@"),
                  !trimmed.hasPrefix("Host_Alias"),
                  !trimmed.hasPrefix("User_Alias"),
                  !trimmed.hasPrefix("Cmnd_Alias"),
                  !trimmed.hasPrefix("Runas_Alias")
            else { continue }

            // Simple heuristic: look for lines with = separator
            guard let eqRange = trimmed.range(of: "=") else { continue }

            let lhs = trimmed[..<eqRange.lowerBound].trimmingCharacters(in: .whitespaces)
            let rhs = trimmed[eqRange.upperBound...].trimmingCharacters(in: .whitespaces)

            // Extract the user list and host from LHS: "alice, bob ALL" -> [alice, bob], ALL
            let compactLHS = lhs.replacingOccurrences(of: #",[ \t]+"#, with: ",", options: .regularExpression)
            let lhsParts = compactLHS.split(maxSplits: 1, omittingEmptySubsequences: true, whereSeparator: Self.isWhitespace)
            guard let users = lhsParts.first else { continue }
            let host = lhsParts.count > 1
                ? String(lhsParts[1]).trimmingCharacters(in: .whitespaces)
                : "ALL"

            let specs = Self.commandSpecs(from: rhs)
            for user in users.split(separator: ",") {
                for spec in specs {
                    rules.append(SudoersRule(
                        user: String(user),
                        host: host,
                        command: spec.command,
                        nopasswd: spec.nopasswd
                    ))
                }
            }
        }

        return rules
    }

    private struct CommandSpec {
        let command: String
        let nopasswd: Bool
    }

    /// Lines with backslash continuations joined. As in sudo, a comment ends at its
    /// newline even when it ends in a backslash, so it cannot swallow the next rule.
    private static func logicalLines(_ content: String) -> [String] {
        var lines: [String] = []
        var pending = ""
        for raw in content.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline) {
            let line = (pending + raw).trimmingCharacters(in: .whitespaces)
            if line.hasSuffix("\\"), !isComment(line) {
                pending = String(line.dropLast()) + " "
            } else {
                lines.append(line)
                pending = ""
            }
        }
        if !pending.isEmpty { lines.append(pending.trimmingCharacters(in: .whitespaces)) }
        return lines
    }

    /// `#` starts a comment unless a digit follows (`#501`, `#-1`): that is a numeric user ID.
    private static func isComment(_ line: String) -> Bool {
        guard line.hasPrefix("#") else { return false }
        let rest = line.dropFirst()
        let digits = rest.first == "-" ? rest.dropFirst() : rest
        return !(digits.first?.isASCII == true && digits.first?.isNumber == true)
    }

    private static func isWhitespace(_ character: Character) -> Bool {
        character == " " || character == "\t"
    }

    /// Split the right-hand side into comma-separated command specifications.
    /// As in sudoers, a `NOPASSWD:`/`PASSWD:` tag applies to the commands that
    /// follow it until another tag changes it.
    private static func commandSpecs(from rhs: String) -> [CommandSpec] {
        var specs: [CommandSpec] = []
        var nopasswd = false

        for item in topLevelItems(rhs) {
            var command = item.trimmingCharacters(in: .whitespaces)
            // Remove (runas) spec
            if command.hasPrefix("("), let parenEnd = command.firstIndex(of: ")") {
                command = String(command[command.index(after: parenEnd)...]).trimmingCharacters(in: .whitespaces)
            }
            command = stripLeadingTags(command, nopasswd: &nopasswd)
            guard !command.isEmpty else { continue }
            specs.append(CommandSpec(command: command, nopasswd: nopasswd))
        }

        return specs
    }

    /// Commas inside a `(runas)` list do not separate command specifications.
    private static func topLevelItems(_ text: String) -> [Substring] {
        var items: [Substring] = []
        var depth = 0
        var start = text.startIndex
        for index in text.indices {
            switch text[index] {
            case "(": depth += 1
            case ")": depth = max(0, depth - 1)
            case "," where depth == 0:
                items.append(text[start..<index])
                start = text.index(after: index)
            default: break
            }
        }
        items.append(text[start...])
        return items
    }

    /// Remove leading `TAG:` tokens (NOPASSWD:, PASSWD:, SETENV:, ...), updating `nopasswd`.
    /// A tag may be followed directly by the command, as in `NOPASSWD:/bin/ls`.
    private static func stripLeadingTags(_ spec: String, nopasswd: inout Bool) -> String {
        var rest = Substring(spec)
        while true {
            if let afterOption = droppingLeadingOption(rest) {
                rest = afterOption
                continue
            }
            guard let colon = rest.firstIndex(of: ":") else { break }
            let tag = rest[..<colon]
            guard !tag.isEmpty, tag.allSatisfy({ $0.isUppercase || $0 == "_" }) else { break }
            if tag == "NOPASSWD" {
                nopasswd = true
            } else if tag == "PASSWD" {
                nopasswd = false
            }
            rest = rest[rest.index(after: colon)...].drop(while: isWhitespace)
        }
        return String(rest)
    }

    /// sudo 1.9 options such as `CWD=*`, `CHROOT=/x` or `TIMEOUT=5m` may precede the tags.
    private static func droppingLeadingOption(_ rest: Substring) -> Substring? {
        let token = rest.prefix { !isWhitespace($0) }
        guard let equals = token.firstIndex(of: "="), equals > token.startIndex,
              token[..<equals].allSatisfy({ $0.isUppercase || $0 == "_" })
        else { return nil }
        return rest[token.endIndex...].drop(while: isWhitespace)
    }
}
