import Foundation
import Models

/// Collects SSH and Screen Sharing remote access service status.
///
/// Checks launchctl for service presence and parses config files.
/// No elevation required for read access to sshd_config or ALF prefs.
public struct RemoteAccessDataSource: DataSource {
    public let name = "Remote Access"
    public let requiresElevation = false

    private let sshdConfigPath: String
    private let launchctlRunner: @Sendable ([String]) -> ShellOutcome

    public init(sshdConfigPath: String = "/etc/ssh/sshd_config") {
        self.sshdConfigPath = sshdConfigPath
        launchctlRunner = { arguments in
            Shell.execute("/bin/launchctl", arguments)
        }
    }

    public init(
        sshdConfigPath: String = "/etc/ssh/sshd_config",
        launchctlRunner: @escaping @Sendable ([String]) -> String?
    ) {
        self.sshdConfigPath = sshdConfigPath
        self.launchctlRunner = { arguments in
            if let output = launchctlRunner(arguments) {
                return .success(ShellResult(
                    stdout: output,
                    stderr: "",
                    terminationStatus: 0,
                    timedOut: false
                ))
            }
            return .nonZeroExit(ShellResult(
                stdout: "",
                stderr: "",
                terminationStatus: 1,
                timedOut: false
            ))
        }
    }

    public func collect() async -> DataSourceResult {
        var errors: [CollectionError] = []
        let ssh = collectSSH(errors: &errors)
        let screenSharing = collectScreenSharing(errors: &errors)
        return DataSourceResult(nodes: [ssh, screenSharing], errors: errors)
    }

    // MARK: - SSH

    private func collectSSH(errors: inout [CollectionError]) -> RemoteAccessService {
        let enabled = detectServiceEnabled(label: "com.openssh.sshd", errors: &errors)
        var config: [String: String] = [:]
        var port: Int? = nil

        if FileManager.default.fileExists(atPath: sshdConfigPath) {
            if let contents = try? String(contentsOfFile: sshdConfigPath, encoding: .utf8) {
                let directives = parseSSHConfig(contents)
                config = directives
                if let portStr = directives["Port"], let p = Int(portStr) {
                    port = p
                }
            } else {
                errors.append(CollectionError(
                    source: name,
                    message: "Cannot read sshd_config at \(sshdConfigPath)",
                    recoverable: true
                ))
            }
        }

        return RemoteAccessService(
            service: RemoteServiceName.ssh,
            enabled: enabled,
            port: port ?? (enabled == true ? 22 : nil),
            config: config
        )
    }

    /// Parses sshd_config for security-relevant directives.
    /// SSH config keys are case-insensitive per sshd_config(5); output uses canonical casing.
    func parseSSHConfig(_ contents: String) -> [String: String] {
        let canonicalKeys: [String: String] = [
            "port": "Port",
            "permitrootlogin": "PermitRootLogin",
            "passwordauthentication": "PasswordAuthentication",
            "pubkeyauthentication": "PubkeyAuthentication",
        ]

        var result: [String: String] = [:]
        for line in contents.components(separatedBy: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty, !trimmed.hasPrefix("#") else { continue }

            let parts = trimmed.split(maxSplits: 1, whereSeparator: \.isWhitespace)
            guard parts.count == 2 else { continue }

            let key = String(parts[0])
            if let canonical = canonicalKeys[key.lowercased()] {
                result[canonical] = String(parts[1])
            }
        }
        return result
    }

    // MARK: - Screen Sharing

    private func collectScreenSharing(errors: inout [CollectionError]) -> RemoteAccessService {
        let enabled = detectServiceEnabled(label: "com.apple.screensharing", errors: &errors)
        return RemoteAccessService(
            service: RemoteServiceName.screenSharing,
            enabled: enabled,
            port: enabled == true ? 5900 : nil,
            config: [:]
        )
    }

    func detectServiceEnabled(label: String, errors: inout [CollectionError]) -> Bool? {
        let disabledOutcome = launchctlRunner(["print-disabled", "system"])
        guard case .success(let disabledResult) = disabledOutcome else {
            errors.append(CollectionError(
                source: name,
                message: "Failed to query launchctl disabled state for \(label): \(disabledOutcome.failureDescription ?? "command failure")",
                recoverable: true
            ))
            return nil
        }
        let disabledOutput = disabledResult.stdout

        if let disabled = Self.parseDisabledServices(output: disabledOutput)[label] {
            return !disabled
        }

        let serviceOutcome = launchctlRunner(["print", "system/\(label)"])
        if case .success = serviceOutcome {
            return true
        }
        if case .nonZeroExit = serviceOutcome {
            return false
        }

        errors.append(CollectionError(
            source: name,
            message: "Failed to query launchctl service state for \(label): \(serviceOutcome.failureDescription ?? "command failure")",
            recoverable: true
        ))
        return nil
    }

    static func parseDisabledServices(output: String) -> [String: Bool] {
        var services: [String: Bool] = [:]
        for line in output.components(separatedBy: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard trimmed.hasPrefix("\"") else { continue }
            let parts = trimmed.components(separatedBy: "=>")
            guard parts.count == 2 else { continue }
            let label = parts[0].trimmingCharacters(in: CharacterSet(charactersIn: "\" \t"))
            let value = parts[1].trimmingCharacters(in: CharacterSet(charactersIn: "; \t"))
            if value == "true" {
                services[label] = true
            } else if value == "false" {
                services[label] = false
            }
        }
        return services
    }
}
