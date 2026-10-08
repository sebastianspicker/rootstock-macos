import Foundation
import Models
import HostCommand

/// Collects SSH and Screen Sharing remote access service status.
///
/// Checks launchctl for service presence and parses config files.
/// No elevation required for read access to sshd_config or ALF prefs.
public struct RemoteAccessDataSource: DataSource {
    public let name = "Remote Access"
    public let requiresElevation = false

    private let sshdConfigPath: String
    private let userSSHDirectory = FileManager.default.homeDirectoryForCurrentUser.path + "/.ssh"
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
            if let data = try? BoundedFileReader.read(path: sshdConfigPath) {
                let contents = String(decoding: data, as: UTF8.self)
                let directives = parseSSHConfig(contents)
                config = directives.merging(Self.normalizedSSHDirectives(directives)) { current, _ in current }
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

        config.merge(userSSHConfig(errors: &errors)) { current, _ in current }

        return RemoteAccessService(
            service: RemoteServiceName.ssh,
            enabled: enabled,
            port: port ?? (enabled == true ? 22 : nil),
            config: config
        )
    }

    /// Parses sshd_config for security-relevant directives (see `SSHDConfigParser`).
    /// SSH config keys are case-insensitive per sshd_config(5); output uses canonical casing.
    func parseSSHConfig(_ contents: String) -> [String: String] {
        var parser = SSHDConfigParser()
        return parser.parse(contents)
    }

    /// Snake-case copies of the security directives with lower-cased values.
    static func normalizedSSHDirectives(_ directives: [String: String]) -> [String: String] {
        let keys = [
            "PermitRootLogin": "permit_root_login",
            "PasswordAuthentication": "password_authentication",
            "PubkeyAuthentication": "pubkey_authentication",
        ]
        var normalized: [String: String] = [:]
        for (directive, key) in keys {
            if let value = directives[directive] {
                normalized[key] = value.lowercased()
            }
        }
        return normalized
    }

    /// `authorized_keys_count` and `agent_forwarding` from the current user's `~/.ssh`.
    /// Only line counts and the `ForwardAgent` directive are recorded, never key material.
    private func userSSHConfig(errors: inout [CollectionError]) -> [String: String] {
        var config: [String: String] = [:]
        if let contents = readUserSSHFile("authorized_keys", errors: &errors) {
            config["authorized_keys_count"] = String(Self.countAuthorizedKeys(contents))
        }
        if let contents = readUserSSHFile("config", errors: &errors) {
            config["agent_forwarding"] = Self.forwardsAgent(contents) ? "yes" : "no"
        }
        return config
    }

    /// Absent files yield nil silently; an existing but unreadable file is one recoverable error.
    private func readUserSSHFile(_ fileName: String, errors: inout [CollectionError]) -> String? {
        let path = "\(userSSHDirectory)/\(fileName)"
        guard FileManager.default.fileExists(atPath: path) else { return nil }
        do {
            return String(decoding: try BoundedFileReader.read(path: path), as: UTF8.self)
        } catch {
            errors.append(CollectionError(
                source: name,
                message: "Cannot read \(path): \(error)",
                recoverable: true
            ))
            return nil
        }
    }

    /// Number of non-empty, non-comment lines in an `authorized_keys` file.
    static func countAuthorizedKeys(_ contents: String) -> Int {
        contents.split(whereSeparator: \.isNewline).filter { line in
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            return !trimmed.isEmpty && !trimmed.hasPrefix("#")
        }.count
    }

    /// True when an ssh client config contains a `ForwardAgent yes` directive.
    static func forwardsAgent(_ contents: String) -> Bool {
        contents.split(whereSeparator: \.isNewline).contains { line in
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.hasPrefix("#") else { return false }
            let parts = trimmed.split(maxSplits: 1, whereSeparator: { $0.isWhitespace || $0 == "=" })
            guard parts.count == 2, parts[0].lowercased() == "forwardagent" else { return false }
            return parts[1].trimmingCharacters(in: CharacterSet(charactersIn: " =\t\"")).lowercased() == "yes"
        }
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
