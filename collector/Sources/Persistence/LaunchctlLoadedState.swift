import Foundation
import HostCommand
import Models

/// Labels launchd currently has loaded, from `launchctl list` (the caller's user domain)
/// and `launchctl print system` (the system domain). A nil set means the command failed,
/// so the loaded state of items in that domain is unknown rather than false.
struct LaunchctlLoadedState: Sendable {
    let userLabels: Set<String>?
    let systemLabels: Set<String>?

    init(userLabels: Set<String>? = nil, systemLabels: Set<String>? = nil) {
        self.userLabels = userLabels
        self.systemLabels = systemLabels
    }

    /// Agents are looked up in the user domain, daemons in the system domain; other types are nil.
    func loaded(label: String, type: LaunchItem.ItemType) -> Bool? {
        switch type {
        case .agent: userLabels.map { $0.contains(label) }
        case .daemon: systemLabels.map { $0.contains(label) }
        case .loginItem, .cron, .loginHook: nil
        }
    }

    /// Runs each launchctl command once. Returns one message per command that failed.
    static func collect(run: ShellCommand = ShellCommandRunner.run) -> (LaunchctlLoadedState, [String]) {
        var errors: [String] = []
        let user = labels(from: run("/bin/launchctl", ["list"], Shell.defaultTimeoutSeconds),
                          command: "launchctl list", parser: parseList, errors: &errors)
        let system = labels(from: run("/bin/launchctl", ["print", "system"], Shell.defaultTimeoutSeconds),
                            command: "launchctl print system", parser: parsePrintServices, errors: &errors)
        return (LaunchctlLoadedState(userLabels: user, systemLabels: system), errors)
    }

    private static func labels(
        from outcome: ShellOutcome,
        command: String,
        parser: (String) -> Set<String>,
        errors: inout [String]
    ) -> Set<String>? {
        guard case .success(let result) = outcome else {
            errors.append("\(command) failed: \(outcome.failureDescription ?? "command failure")")
            return nil
        }
        return parser(result.stdout)
    }

    /// Parse `launchctl list`: a `PID\tStatus\tLabel` header followed by one job per line.
    static func parseList(_ output: String) -> Set<String> {
        var labels: Set<String> = []
        for line in output.split(separator: "\n") {
            let columns = line.split(separator: "\t", maxSplits: 2, omittingEmptySubsequences: false)
            guard columns.count == 3, columns[0] != "PID" else { continue }
            let label = columns[2].trimmingCharacters(in: .whitespaces)
            if !label.isEmpty { labels.insert(label) }
        }
        return labels
    }

    /// Parse the `services = { … }` block of `launchctl print system`
    /// (lines of the form `<pid|-> <status|-> <label>`).
    static func parsePrintServices(_ output: String) -> Set<String> {
        var labels: Set<String> = []
        var inServices = false
        for line in output.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if !inServices {
                inServices = trimmed == "services = {"
                continue
            }
            if trimmed == "}" { break }
            let parts = trimmed.split(maxSplits: 2, omittingEmptySubsequences: true) { $0 == " " || $0 == "\t" }
            guard parts.count == 3, parts[0] == "-" || Int(parts[0]) != nil else { continue }
            labels.insert(parts[2].trimmingCharacters(in: .whitespaces))
        }
        return labels
    }
}
