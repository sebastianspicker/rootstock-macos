import Foundation
import Models

/// Enumerates system extensions via `systemextensionsctl list`.
public struct SystemExtensionDataSource: DataSource {
    public let name = "System Extensions"
    public let requiresElevation = false

    public init() {}

    public func collect() async -> DataSourceResult {
        guard let output = Shell.run("/usr/bin/systemextensionsctl", ["list"]) else {
            return DataSourceResult(
                nodes: [],
                errors: [CollectionError(source: name, message: "Failed to run systemextensionsctl", recoverable: true)]
            )
        }

        let extensions = Self.parseSystemExtensionsOutput(output)
        return DataSourceResult(nodes: extensions, errors: [])
    }

    /// Parse `systemextensionsctl list` output.
    /// Lines look like: `---  com.crowdstrike.falcon.Agent (1.0/1.0)  TeamID  [activated enabled]`
    ///
    /// Uses a regex-based parser as the primary method for robustness, with
    /// the original heuristic parser as a fallback for unexpected formats.
    internal static func parseSystemExtensionsOutput(_ output: String) -> [SystemExtension] {
        let regexResult = parseWithRegex(output)
        if !regexResult.isEmpty {
            return regexResult
        }
        // Fallback to heuristic parser for unexpected output formats
        return parseWithHeuristic(output)
    }

    // MARK: - Regex-based parser (primary)

    /// Regex-based parser that handles known `systemextensionsctl list` output formats.
    ///
    /// Supported formats:
    ///   - `--- com.example.ext (1.0/1.0)  TEAMID1234  [activated enabled]`
    ///   - `*   com.example.ext (1.0/1.0)  TEAMID1234  [activated enabled]`
    ///   - Lines without version parenthetical
    ///   - State strings like `[activated enabled]`, `[activated waiting for user]`, etc.
    private static func parseWithRegex(_ output: String) -> [SystemExtension] {
        // Match: optional prefix (--- or *), bundle identifier (reverse-DNS with dots),
        //        optional (version), optional TeamID (10 alphanum chars), optional [state]
        let pattern = #"^[\s]*(?:---|\*)\s+([\w.-]+(?:\.[\w.-]+)+)\s*(?:\([^)]*\))?\s*([A-Z0-9]{10})?\s*(?:\[([^\]]*)\])?"#
        guard let regex = try? NSRegularExpression(pattern: pattern, options: .anchorsMatchLines) else {
            return []
        }

        var extensions: [SystemExtension] = []
        let nsOutput = output as NSString
        let matches = regex.matches(in: output, range: NSRange(location: 0, length: nsOutput.length))

        for match in matches {
            // Group 1: identifier (always present if matched)
            guard match.numberOfRanges >= 2,
                  match.range(at: 1).location != NSNotFound else { continue }
            let identifier = nsOutput.substring(with: match.range(at: 1))

            // Group 2: teamId (optional)
            var teamId: String? = nil
            if match.numberOfRanges >= 3, match.range(at: 2).location != NSNotFound {
                teamId = nsOutput.substring(with: match.range(at: 2))
            }

            // Group 3: state string inside brackets (optional)
            var enabled = false
            if match.numberOfRanges >= 4, match.range(at: 3).location != NSNotFound {
                let state = nsOutput.substring(with: match.range(at: 3))
                enabled = state.contains("enabled")
            }

            let extType = classifyExtensionType(identifier)
            let fullLine = nsOutput.substring(with: match.range(at: 0))
            let subscribedEvents = parseSubscribedEvents(fullLine)

            extensions.append(SystemExtension(
                identifier: identifier,
                teamId: teamId,
                extensionType: extType,
                enabled: enabled,
                subscribedEvents: subscribedEvents
            ))
        }

        return extensions
    }

    // MARK: - Heuristic parser (fallback)

    /// Original heuristic-based parser kept as a fallback for output formats
    /// not matched by the regex parser.
    private static func parseWithHeuristic(_ output: String) -> [SystemExtension] {
        var extensions: [SystemExtension] = []

        for line in output.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            // Skip header lines and pure separator lines (but not data lines prefixed with ---)
            guard !trimmed.isEmpty,
                  !trimmed.allSatisfy({ $0 == "-" || $0 == "=" }),
                  !trimmed.hasPrefix("System Extension"),
                  !trimmed.hasPrefix("enabled")
            else { continue }
            // Strip leading "--- " or "*   " prefix used by systemextensionsctl
            let stripped: String
            if trimmed.hasPrefix("---") || trimmed.hasPrefix("*") {
                let afterPrefix = trimmed.drop(while: { $0 == "-" || $0 == "*" || $0 == " " })
                stripped = String(afterPrefix)
            } else {
                stripped = trimmed
            }

            // Parse: `identifier (version)  teamID  [state]`
            let parts = stripped.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
            guard parts.count >= 2 else { continue }

            // Find the identifier (contains a dot like com.xxx.yyy)
            var identifier: String?
            var teamId: String?
            // Check the full line for "enabled" — the bracketed state like
            // "[activated enabled]" splits across multiple tokens
            let enabled = stripped.contains("enabled")

            for part in parts {
                if part.contains(".") && !part.hasPrefix("[") && !part.hasPrefix("(") {
                    if identifier == nil {
                        identifier = part
                    }
                }
            }

            // TeamID is typically a 10-char alphanumeric string
            for part in parts {
                if part.count == 10 && part.allSatisfy({ $0.isLetter || $0.isNumber }) && part != identifier {
                    teamId = part
                    break
                }
            }

            guard let id = identifier else { continue }

            let extType = classifyExtensionType(id)
            let subscribedEvents = Self.parseSubscribedEvents(stripped)

            extensions.append(SystemExtension(
                identifier: id,
                teamId: teamId,
                extensionType: extType,
                enabled: enabled,
                subscribedEvents: subscribedEvents
            ))
        }

        return extensions
    }

    // MARK: - Shared helpers

    /// Determine extension type from identifier patterns.
    private static func classifyExtensionType(_ identifier: String) -> SystemExtension.ExtensionType {
        if identifier.contains("network") || identifier.contains("dns") || identifier.contains("vpn") || identifier.contains("firewall") {
            return .network
        } else if identifier.contains("endpoint") || identifier.contains("security") || identifier.contains("falcon") || identifier.contains("sentinel") {
            return .endpointSecurity
        } else {
            return .driver
        }
    }

    /// Parse ESF event subscriptions from systemextensionsctl output.
    /// Looks for patterns like "events=[AUTH_EXEC,NOTIFY_FORK]" or "events: AUTH_EXEC, NOTIFY_FORK".
    internal static func parseSubscribedEvents(_ line: String) -> [String] {
        // Pattern 1: events=[EVENT1,EVENT2]
        if let range = line.range(of: "events=\\[[^\\]]*\\]", options: .regularExpression) {
            let eventsStr = line[range]
            let inner = eventsStr.dropFirst("events=[".count).dropLast(1)
            return inner.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        }
        // Pattern 2: events: EVENT1, EVENT2
        if let range = line.range(of: "events:\\s*[A-Z_,\\s]+", options: .regularExpression) {
            let eventsStr = String(line[range]).replacingOccurrences(of: "events:", with: "").trimmingCharacters(in: .whitespaces)
            return eventsStr.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        }
        return []
    }
}
