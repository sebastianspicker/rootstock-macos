import Foundation
import Models

/// Enumerates active login sessions by parsing the output of `who`.
public struct LoginSessionDataSource: DataSource {
    public let name = "Login Sessions"
    public let requiresElevation = false

    public init() {}

    public func collect() async -> DataSourceResult {
        guard let output = Shell.run("/usr/bin/who", []) else {
            return DataSourceResult(
                nodes: [],
                errors: [CollectionError(source: name, message: "Failed to run 'who' command", recoverable: true)]
            )
        }

        let sessions = Self.parseWhoOutput(output)
        return DataSourceResult(nodes: sessions, errors: [])
    }

    /// Parse `who` output into LoginSession objects.
    /// Format: `username  terminal  login_date login_time  (host)`
    /// Example: `sebastian  console  Mar 18 09:15`
    /// Example: `sebastian  ttys000  Mar 18 09:30 (192.168.1.5)`
    internal static func parseWhoOutput(_ output: String) -> [LoginSession] {
        var sessions: [LoginSession] = []

        for line in output.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty else { continue }

            let parts = trimmed.split(separator: " ", omittingEmptySubsequences: true)
            guard parts.count >= 3 else { continue }

            let username = String(parts[0])
            let terminal = String(parts[1])

            // Login time is everything after the terminal, before any (host) marker
            let afterTerminal = parts[2...]
            var timeParts: [String] = []
            for part in afterTerminal {
                if part.hasPrefix("(") { break }
                timeParts.append(String(part))
            }
            let loginTime = timeParts.joined(separator: " ")

            // Determine session type from terminal name and optional host
            let host = afterTerminal.last.flatMap { p -> String? in
                let s = String(p)
                guard s.hasPrefix("(") && s.hasSuffix(")") else { return nil }
                return String(s.dropFirst().dropLast())
            }

            let sessionType = classifySession(terminal: terminal, host: host)

            sessions.append(LoginSession(
                username: username,
                terminal: terminal,
                loginTime: loginTime,
                sessionType: sessionType
            ))
        }

        return sessions
    }

    private static func classifySession(terminal: String, host: String?) -> LoginSession.SessionType {
        if terminal == "console" {
            return .console
        }
        if let h = host {
            if h.contains("tmux") || h.contains("screen") {
                return .tmux
            }
            // Remote connection via SSH or screen sharing
            return .ssh
        }
        // Local terminal session — could be tmux but default to console
        return .console
    }
}
