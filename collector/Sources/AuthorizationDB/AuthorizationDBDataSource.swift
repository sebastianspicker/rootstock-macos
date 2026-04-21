import Foundation
import Models

/// Reads macOS Authorization Database rights via `security authorizationdb read`.
///
/// Checks 7 key rights that control privilege escalation, service installation,
/// and system configuration access.
public struct AuthorizationDBDataSource: DataSource {
    public let name = "Authorization DB"
    public let requiresElevation = false

    /// Key authorization rights to audit.
    static let keyRights = [
        "system.privilege.admin",
        "system.login.console",
        "system.preferences",
        "system.install.apple-software",
        "com.apple.ServiceManagement.blesshelper",
        "system.preferences.security",
        "system.privilege.taskport",
    ]

    public init() {}

    public func collect() async -> DataSourceResult {
        var rights: [AuthorizationRight] = []
        var errors: [CollectionError] = []

        for rightName in Self.keyRights {
            let (right, error) = readRight(rightName)
            if let right {
                rights.append(right)
            }
            if let error {
                errors.append(CollectionError(source: name, message: error, recoverable: true))
            }
        }

        return DataSourceResult(nodes: rights, errors: errors)
    }

    // MARK: - Private

    private func readRight(_ rightName: String) -> (AuthorizationRight?, String?) {
        guard let output = Shell.run("/usr/bin/security", ["authorizationdb", "read", rightName]) else {
            return (nil, "Failed to read authorization right: \(rightName)")
        }
        return Self.parseSecurityOutput(rightName: rightName, output: output)
    }

    /// Parse plist output from `security authorizationdb read <right>`.
    internal static func parseSecurityOutput(rightName: String, output: String) -> (AuthorizationRight?, String?) {
        guard let data = output.data(using: .utf8),
              let plist = Shell.parsePlistDict(from: data) else {
            return (nil, "Cannot parse plist for right: \(rightName)")
        }

        let rule = plist["rule"] as? String
            ?? (plist["rule"] as? [String])?.first
        let allowRoot = plist["allow-root"] as? Bool ?? false
        let requireAuth = plist["authenticate-user"] as? Bool ?? true

        return (AuthorizationRight(
            name: rightName,
            rule: rule,
            allowRoot: allowRoot,
            requireAuthentication: requireAuth
        ), nil)
    }
}
