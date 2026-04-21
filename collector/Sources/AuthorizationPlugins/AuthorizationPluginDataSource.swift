import Foundation
import Models

/// Scans /Library/Security/SecurityAgentPlugins/ for authorization plugin bundles.
public struct AuthorizationPluginDataSource: DataSource {
    public let name = "Authorization Plugins"
    public let requiresElevation = false

    private static let pluginDir = "/Library/Security/SecurityAgentPlugins"

    public init() {}

    public func collect() async -> DataSourceResult {
        let fm = FileManager.default

        guard let contents = try? fm.contentsOfDirectory(atPath: Self.pluginDir) else {
            return DataSourceResult(
                nodes: [],
                errors: [CollectionError(source: name, message: "Cannot read \(Self.pluginDir)", recoverable: true)]
            )
        }

        var plugins: [AuthorizationPlugin] = []
        for item in contents where item.hasSuffix(".bundle") {
            let bundlePath = (Self.pluginDir as NSString).appendingPathComponent(item)
            let pluginName = (item as NSString).deletingPathExtension
            let teamId = extractTeamId(at: bundlePath)

            plugins.append(AuthorizationPlugin(
                name: pluginName,
                path: bundlePath,
                teamId: teamId
            ))
        }

        return DataSourceResult(nodes: plugins, errors: [])
    }

    /// Extract TeamIdentifier from codesign verbose output (written to stderr).
    private func extractTeamId(at path: String) -> String? {
        guard let output = Shell.runStderr("/usr/bin/codesign", ["-d", "--verbose=2", path]) else {
            return nil
        }
        for line in output.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("TeamIdentifier=") {
                let value = String(trimmed.dropFirst("TeamIdentifier=".count))
                return value == "not set" ? nil : value
            }
        }
        return nil
    }
}
