import Foundation
import Models
import RootstockMacFacts
import HostCommand

/// Scans /Library/Security/SecurityAgentPlugins/ for authorization plugin bundles.
public struct AuthorizationPluginDataSource: DataSource {
    public let name = "Authorization Plugins"
    public let requiresElevation = false

    private static let pluginDir = MacSecurityPaths.authorizationPlugins

    public init() {}

    public func collect() async -> DataSourceResult {
        let fm = FileManager.default

        guard let contents = (try? fm.contentsOfDirectory(atPath: Self.pluginDir))?.sorted() else {
            return DataSourceResult(
                nodes: [],
                errors: [CollectionError(source: name, message: "Cannot read \(Self.pluginDir)", recoverable: true)]
            )
        }

        var plugins: [AuthorizationPlugin] = []
        var errors: [CollectionError] = []
        for item in contents where item.hasSuffix(".bundle") {
            let bundlePath = (Self.pluginDir as NSString).appendingPathComponent(item)
            let pluginName = (item as NSString).deletingPathExtension
            let teamIDResult = extractTeamId(at: bundlePath)
            if let error = teamIDResult.error {
                errors.append(error)
            }

            plugins.append(AuthorizationPlugin(
                name: pluginName,
                path: bundlePath,
                teamId: teamIDResult.teamID
            ))
        }

        return DataSourceResult(nodes: plugins, errors: errors)
    }

    /// Extract TeamIdentifier from codesign verbose output (written to stderr).
    private func extractTeamId(
        at path: String
    ) -> (teamID: String?, error: CollectionError?) {
        let outcome = Shell.execute("/usr/bin/codesign", ["-d", "--verbose=2", path])
        let result: ShellResult
        switch outcome {
        case .success(let successfulResult):
            result = successfulResult
        case .nonZeroExit(let failedResult):
            // A genuinely unsigned bundle has no team identifier; any other
            // failure leaves it unknown.
            if failedResult.stderr.contains("not signed at all") {
                return (nil, nil)
            }
            return (nil, CollectionError(
                source: name,
                message: "Team identifier unknown for \(path): \(outcome.failureDescription ?? "command failure")",
                recoverable: true
            ))
        case .admissionTimedOut, .launchFailed, .executionTimedOut:
            return (nil, CollectionError(
                source: name,
                message: "Team identifier unknown for \(path): \(outcome.failureDescription ?? "command failure")",
                recoverable: true
            ))
        }
        let output = result.stderr
        for line in output.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("TeamIdentifier=") {
                let value = String(trimmed.dropFirst("TeamIdentifier=".count))
                return (value == "not set" ? nil : value, nil)
            }
        }
        return (nil, nil)
    }
}
