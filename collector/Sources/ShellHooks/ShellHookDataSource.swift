import Foundation
import Models
import FileACLs

/// Collects shell hook file metadata for persistence and credential theft analysis.
///
/// Checks existence and writability of shell RC files (~/.zshrc, ~/.bashrc, etc.)
/// and system-wide shell configuration. These are modeled as CriticalFile nodes
/// with category "shell_hook" - writable shell hooks enable code injection on
/// every interactive shell session.
public struct ShellHookDataSource: DataSource {
    public let name = "Shell Hooks"
    public let requiresElevation = false

    /// Shell hook paths to check. Tilde-prefixed paths are per-user.
    static let hookPaths: [String] = [
        "~/.zshrc",
        "~/.bashrc",
        "~/.profile",
        "~/.zshenv",
        "~/.zprofile",
        "~/.bash_profile",
        "~/.ssh/rc",
        "/etc/zshrc",
        "/etc/profile",
        "/etc/zshenv",
    ]

    public init() {}

    public func collect() async -> DataSourceResult {
        var results: [FileACL] = []
        var errors: [CollectionError] = []
        let fm = FileManager.default

        for rawPath in Self.hookPaths {
            let path = FileACLDataSource.expandTilde(rawPath)
            let (fileACL, error) = FileACLDataSource().collectPath(
                path,
                category: "shell_hook",
                fm: fm,
                reportsACLErrors: false
            )
            if let fileACL {
                results.append(fileACL)
            }
            if let error {
                errors.append(CollectionError(source: name, message: error, recoverable: true))
            }
        }

        return DataSourceResult(nodes: results, errors: errors)
    }
}
