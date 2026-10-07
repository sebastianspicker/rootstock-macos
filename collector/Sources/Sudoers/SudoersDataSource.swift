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
            let content = try String(contentsOfFile: path, encoding: .utf8)
            return (Self.parseSudoersContent(content), [])
        } catch let error as NSError where error.domain == NSCocoaErrorDomain && error.code == NSFileReadNoSuchFileError {
            return ([], ["Cannot read sudoers file: \(path)"])
        } catch {
            return ([], ["Cannot read sudoers file (requires elevation): \(path)"])
        }
    }

    /// Parse sudoers file content for user rules.
    /// Format: `user  host = (runas) [NOPASSWD:] command`
    internal static func parseSudoersContent(_ content: String) -> [SudoersRule] {
        var rules: [SudoersRule] = []

        for line in content.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            // Skip comments (including #include/#includedir directives),
            // Defaults, aliases, and @include directives.
            // Note: #include to non-standard paths is not followed;
            // /etc/sudoers.d/ is enumerated separately by the caller.
            guard !trimmed.isEmpty,
                  !trimmed.hasPrefix("#"),
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

            // Extract user and host from LHS
            let lhsParts = lhs.split(maxSplits: 1, omittingEmptySubsequences: true, whereSeparator: Self.isWhitespace)
            guard let user = lhsParts.first else { continue }
            let host = lhsParts.count > 1
                ? String(lhsParts[1]).trimmingCharacters(in: .whitespaces)
                : "ALL"

            for spec in Self.commandSpecs(from: rhs) {
                rules.append(SudoersRule(
                    user: String(user),
                    host: host,
                    command: spec.command,
                    nopasswd: spec.nopasswd
                ))
            }
        }

        return rules
    }

    private struct CommandSpec {
        let command: String
        let nopasswd: Bool
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

        for item in rhs.split(separator: ",") {
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

    /// Remove leading `TAG:` tokens (NOPASSWD:, PASSWD:, SETENV:, ...), updating `nopasswd`.
    private static func stripLeadingTags(_ spec: String, nopasswd: inout Bool) -> String {
        var rest = spec
        while let first = rest.split(maxSplits: 1, whereSeparator: isWhitespace).first {
            let tag = String(first)
            guard tag.count > 1, tag.hasSuffix(":"),
                  tag.dropLast().allSatisfy({ $0.isUppercase || $0 == "_" }) else { break }
            if tag == "NOPASSWD:" {
                nopasswd = true
            } else if tag == "PASSWD:" {
                nopasswd = false
            }
            rest = String(rest.dropFirst(tag.count)).trimmingCharacters(in: .whitespaces)
        }
        return rest
    }
}
