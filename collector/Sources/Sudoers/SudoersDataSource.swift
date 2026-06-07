import Foundation
import Models

/// Parses /etc/sudoers and /etc/sudoers.d/* for NOPASSWD rules.
public struct SudoersDataSource: DataSource {
    public let name = "Sudoers"
    public let requiresElevation = false

    private let sudoersPath: String
    private let includeDirectoryPath: String

    public init() {
        self.init(sudoersPath: "/etc/sudoers", includeDirectoryPath: "/etc/sudoers.d")
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
                let files = try fm.contentsOfDirectory(atPath: includeDirectoryPath)
                for file in files where !file.hasPrefix(".") {
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
            let lhsParts = lhs.split(separator: " ", maxSplits: 1, omittingEmptySubsequences: true)
            guard let user = lhsParts.first else { continue }
            let host = lhsParts.count > 1 ? String(lhsParts[1]) : "ALL"

            // Check for NOPASSWD in RHS
            let nopasswd = rhs.contains("NOPASSWD")

            // Extract command (strip runas and NOPASSWD tags)
            var command = rhs
            // Remove (runas) spec
            if command.firstIndex(of: "(") != nil,
               let parenEnd = command.firstIndex(of: ")") {
                command = String(command[command.index(after: parenEnd)...]).trimmingCharacters(in: .whitespaces)
            }
            // Remove NOPASSWD: or PASSWD: tags
            command = command.replacingOccurrences(of: "NOPASSWD:", with: "")
                .replacingOccurrences(of: "PASSWD:", with: "")
                .trimmingCharacters(in: .whitespaces)

            guard !command.isEmpty else { continue }

            rules.append(SudoersRule(
                user: String(user),
                host: host,
                command: command,
                nopasswd: nopasswd
            ))
        }

        return rules
    }
}
