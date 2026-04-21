import Foundation
import Models
import FileACLs

/// Collects shell hook file metadata for persistence and credential theft analysis.
///
/// Checks existence and writability of shell RC files (~/.zshrc, ~/.bashrc, etc.)
/// and system-wide shell configuration. These are modeled as CriticalFile nodes
/// with category "shell_hook" — writable shell hooks enable code injection on
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

            guard fm.fileExists(atPath: path) else { continue }

            let attrs: [FileAttributeKey: Any]
            do {
                attrs = try fm.attributesOfItem(atPath: path)
            } catch {
                errors.append(CollectionError(
                    source: name,
                    message: "Cannot read attributes of \(path): \(error.localizedDescription)",
                    recoverable: true
                ))
                continue
            }

            let owner = attrs[.ownerAccountName] as? String ?? "unknown"
            let group = attrs[.groupOwnerAccountName] as? String ?? "unknown"
            let posixPerms = attrs[.posixPermissions] as? Int ?? 0
            let mode = String(format: "%o", posixPerms)

            let aclEntries = FileACLDataSource.readACLEntries(path: path)
            let isWritableByNonRoot = FileACLDataSource.checkWritableByNonRoot(
                posixPerms: posixPerms, owner: owner, aclEntries: aclEntries
            )

            results.append(FileACL(
                path: path,
                owner: owner,
                group: group,
                mode: mode,
                aclEntries: aclEntries,
                isSipProtected: false,
                isWritableByNonRoot: isWritableByNonRoot,
                category: "shell_hook"
            ))
        }

        return DataSourceResult(nodes: results, errors: errors)
    }
}
