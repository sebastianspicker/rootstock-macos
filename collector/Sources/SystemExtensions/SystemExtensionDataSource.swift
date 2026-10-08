import Foundation
import Models
import HostCommand

/// Enumerates system extensions via `systemextensionsctl list` and third-party
/// kernel extensions via `kmutil showloaded`.
public struct SystemExtensionDataSource: DataSource {
    public let name = "System Extensions"
    public let requiresElevation = false

    public init() {}

    public func collect() async -> DataSourceResult {
        var extensions: [SystemExtension] = []
        var errors: [CollectionError] = []
        if let output = Shell.run("/usr/bin/systemextensionsctl", ["list"]) {
            extensions = Self.parseSystemExtensionsOutput(output)
        } else {
            errors.append(CollectionError(source: name, message: "Failed to run systemextensionsctl", recoverable: true))
        }

        let kmutil = Shell.execute("/usr/bin/kmutil", ["showloaded", "--list-only", "--no-kernel-components"])
        if case .success(let result) = kmutil {
            extensions.append(contentsOf: Self.parseLoadedKernelExtensions(result.stdout))
        } else {
            errors.append(CollectionError(
                source: name,
                message: "Failed to run kmutil showloaded: \(kmutil.failureDescription ?? "unknown failure")",
                recoverable: true
            ))
        }
        return DataSourceResult(nodes: extensions, errors: errors)
    }

    /// Parse `kmutil showloaded --list-only` output into third-party kernel extensions.
    /// A row's bundle id is the token followed by its `(version)`; a bare bundle-id line
    /// is accepted too. Apple kexts (`com.apple.`) are skipped and ids are deduplicated.
    internal static func parseLoadedKernelExtensions(_ output: String) -> [SystemExtension] {
        var seen = Set<String>()
        var extensions: [SystemExtension] = []
        for line in output.split(whereSeparator: \.isNewline) {
            guard let identifier = kernelExtensionIdentifier(String(line)),
                  !identifier.hasPrefix("com.apple."),
                  seen.insert(identifier).inserted else { continue }
            extensions.append(SystemExtension(
                identifier: identifier,
                teamId: nil,
                extensionType: .kernelExtension,
                enabled: true,
                subscribedEvents: []
            ))
        }
        return extensions
    }

    private static func kernelExtensionIdentifier(_ line: String) -> String? {
        let tokens = line.split(whereSeparator: \.isWhitespace).map(String.init)
        if tokens.count == 1, isBundleIdentifier(tokens[0]) {
            return tokens[0]
        }
        for index in tokens.indices.dropLast() where tokens[index + 1].hasPrefix("(") {
            if isBundleIdentifier(tokens[index]) { return tokens[index] }
        }
        return nil
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
