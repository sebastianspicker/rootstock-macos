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
    /// Apple has changed this command's row format across releases, so parsing
    /// stays tolerant but still requires a bundle identifier plus lifecycle
    /// state, team ID, or ESF event list to avoid treating headers as data.
    internal static func parseSystemExtensionsOutput(_ output: String) -> [SystemExtension] {
        output.split(whereSeparator: \.isNewline).compactMap { line in
            parseSystemExtensionLine(String(line))
        }
    }

    private static func parseSystemExtensionLine(_ line: String) -> SystemExtension? {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return nil }

        let tokens = trimmed.split(whereSeparator: \.isWhitespace).map(String.init)
        guard hasSystemExtensionRowMarker(tokens) else { return nil }

        guard let identifier = tokens.first(where: isBundleIdentifier) else {
            return nil
        }

        let teamId = tokens.first { token in
            token != identifier && isTeamIdentifier(token)
        }
        let subscribedEvents = parseSubscribedEvents(trimmed)
        guard hasExtensionEvidence(teamId: teamId, subscribedEvents: subscribedEvents, line: trimmed) else {
            return nil
        }

        return SystemExtension(
            identifier: identifier,
            teamId: teamId,
            extensionType: classifyExtensionType(identifier),
            enabled: isEnabled(tokens: tokens, line: trimmed),
            subscribedEvents: subscribedEvents
        )
    }

    private static func hasSystemExtensionRowMarker(_ tokens: [String]) -> Bool {
        guard let firstToken = tokens.first else { return false }
        return firstToken == "---" || firstToken == "*" || firstToken == "-"
    }

    private static func hasExtensionEvidence(
        teamId: String?,
        subscribedEvents: [String],
        line: String
    ) -> Bool {
        teamId != nil || hasLifecycleState(in: line) || !subscribedEvents.isEmpty
    }

    private static func isBundleIdentifier(_ token: String) -> Bool {
        guard token.contains("."),
              !token.hasPrefix("("),
              !token.hasPrefix("["),
              !token.hasSuffix(":")
        else { return false }

        let segments = token.split(separator: ".", omittingEmptySubsequences: false)
        guard segments.count >= 2, segments.allSatisfy({ !$0.isEmpty }) else {
            return false
        }
        return token.allSatisfy { character in
            character.isLetter || character.isNumber || character == "." || character == "-" || character == "_"
        }
    }

    private static func isTeamIdentifier(_ token: String) -> Bool {
        token.count == 10 && token.allSatisfy { $0.isLetter || $0.isNumber }
    }

    private static func isEnabled(tokens: [String], line: String) -> Bool {
        if bracketedSegments(in: line).contains(where: { segment in
            segment.lowercased().split(whereSeparator: { !$0.isLetter }).contains("enabled")
        }) {
            return true
        }

        return isStatusTableRow(tokens) && tokens[0] == "*"
    }

    private static func isStatusTableRow(_ tokens: [String]) -> Bool {
        guard tokens.count >= 4 else { return false }
        return (tokens[0] == "*" || tokens[0] == "-") &&
            (tokens[1] == "*" || tokens[1] == "-") &&
            isTeamIdentifier(tokens[2]) &&
            isBundleIdentifier(tokens[3])
    }

    private static func hasLifecycleState(in line: String) -> Bool {
        bracketedSegments(in: line).contains { segment in
            let state = segment.lowercased()
            return state.contains("activated") ||
                state.contains("enabled") ||
                state.contains("disabled") ||
                state.contains("waiting")
        }
    }

    private static func bracketedSegments(in line: String) -> [String] {
        var segments: [String] = []
        var searchStart = line.startIndex

        while let open = line[searchStart...].firstIndex(of: "[") {
            let afterOpen = line.index(after: open)
            guard let close = line[afterOpen...].firstIndex(of: "]") else {
                break
            }
            segments.append(String(line[afterOpen..<close]))
            searchStart = line.index(after: close)
        }
        return segments
    }

    /// Determine extension type from identifier patterns.
    private static func classifyExtensionType(_ identifier: String) -> SystemExtension.ExtensionType {
        let identifier = identifier.lowercased()
        if containsAny(["network", "dns", "vpn", "firewall"], in: identifier) {
            return .network
        }
        if containsAny(["endpoint", "security", "falcon", "sentinel"], in: identifier) {
            return .endpointSecurity
        }
        return .driver
    }

    private static func containsAny(_ keywords: [String], in value: String) -> Bool {
        keywords.contains { value.contains($0) }
    }

    /// Parse ESF event subscriptions from systemextensionsctl output.
    /// Looks for patterns like "events=[AUTH_EXEC,NOTIFY_FORK]" or "events: AUTH_EXEC, NOTIFY_FORK".
    internal static func parseSubscribedEvents(_ line: String) -> [String] {
        if let marker = line.range(of: "events=[", options: .caseInsensitive),
           let close = line[marker.upperBound...].firstIndex(of: "]") {
            return splitEvents(String(line[marker.upperBound..<close]))
        }

        if let marker = line.range(of: "events:", options: .caseInsensitive) {
            let suffix = line[marker.upperBound...]
            let eventText: String
            if let stateStart = suffix.firstIndex(of: "[") {
                eventText = String(suffix[..<stateStart])
            } else {
                eventText = String(suffix)
            }
            return splitEvents(eventText)
        }
        return []
    }

    private static func splitEvents(_ value: String) -> [String] {
        value.split(separator: ",").map { event in
            event.trimmingCharacters(in: .whitespaces)
        }.filter { !$0.isEmpty }
    }
}
